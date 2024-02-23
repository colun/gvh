package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/slices"

	"github.com/gorilla/websocket"
)

var verbose = flag.Bool("verbose", false, "verbose")
var public_listen = flag.Bool("public", false, "public listen")
var https_listen = flag.Bool("https", false, "https listen")

type MyChannel struct {
	mu  *sync.Mutex
	ch  chan string
	ins []*websocket.Conn
	del []*websocket.Conn
	inp []*websocket.Conn
}

var channels map[string]*MyChannel
var channels_mu sync.Mutex

func MyWriteMessage(conn *websocket.Conn, message string) {
	conn.WriteMessage(websocket.TextMessage, []byte(message))
}

func worker(mch *MyChannel, ch_name string) {
	conns := []*websocket.Conn{}
	long_snaps := []string{}
	short_snaps := []string{}
	saved_index := 0
	input_mode := false
	keyboard := []string{}
	all_keyboard := false
	ticker := time.NewTicker(time.Millisecond * 10)
	ticker.Stop()
	ticker_flag := 2
	for {
		select {
		case line := <-mch.ch:
			if ticker_flag == 2 {
				ticker.Reset(time.Millisecond * 10)
			}
			ticker_flag = 0
			if *verbose {
				log.Printf("%s(%d): %s", ch_name, len(conns), line)
			}
			tokens := strings.Split(line, " ")
			ty := tokens[0]
			if ty == "register" {
				if 1 <= len(conns) && 1 <= len(short_snaps) {
					message := strings.Join(short_snaps, "\n") + "\n"
					for _, conn := range conns {
						MyWriteMessage(conn, message)
					}
				}
				short_snaps = []string{}
				mch.mu.Lock()
				if 1 <= len(mch.ins) {
					var message string
					if 1 <= len(long_snaps) {
						message = strings.Join(long_snaps, "\n") + "\n"
					}
					if all_keyboard {
						message += "ik all\n"
					} else {
						for _, kg := range keyboard {
							message += "ik " + kg + "\n"
						}
					}
					if input_mode {
						message += "i\n"
					}
					for _, conn := range mch.ins {
						if 1 <= len(message) {
							MyWriteMessage(conn, message)
						}
						conns = append(conns, conn)
					}
					mch.ins = []*websocket.Conn{}
				}
				mch.mu.Unlock()
			} else if ty == "flush" || ty == "f" || ty == "i" {
				if ty == "i" {
					if !input_mode {
						input_mode = true
						short_snaps = append(short_snaps, "i")
					}
				}
				if 1 <= len(short_snaps) {
					if 1 <= len(conns) {
						message := strings.Join(short_snaps, "\n") + "\n"
						for _, conn := range conns {
							MyWriteMessage(conn, message)
						}
					}
					short_snaps = []string{}
				}
				fmt.Fprintf(os.Stderr, "%d %d\r", len(conns), len(long_snaps))
			} else if ty == "unregister" {
				mch.mu.Lock()
				if 1 <= len(mch.del) {
					filtered := []*websocket.Conn{}
					for _, conn := range conns {
						if !slices.Contains(mch.del, conn) {
							filtered = append(filtered, conn)
						}
					}
					conns = filtered
					mch.del = []*websocket.Conn{}
				}
				mch.mu.Unlock()
			} else if ty == "r" {
				del_count := len(long_snaps) - saved_index
				long_snaps = long_snaps[:saved_index]
				if *verbose {
					log.Printf("rollback %d %d %d", del_count, saved_index, len(long_snaps))
				}
				if del_count <= len(short_snaps) {
					short_snaps = short_snaps[:len(short_snaps)-del_count]
				} else {
					short_snaps = append(short_snaps, line)
				}
			} else if ty == "ra" {
				long_snaps = []string{}
				short_snaps = []string{"ra"}
				saved_index = 0
			} else if ty == "init" {
				long_snaps = []string{}
				short_snaps = []string{"init"}
				saved_index = 0
				input_mode = false
				keyboard = []string{}
				all_keyboard = false
			} else if ty == "k" {
				mch.mu.Lock()
				if 1 <= len(mch.inp) {
					ws := mch.inp[0]
					mch.inp = mch.inp[1:]
					mch.mu.Unlock()
					if ws == nil {
						fmt.Fprintln(os.Stdout, line)
					} else {
						MyWriteMessage(ws, line+"\n")
					}
					if 1 <= len(mch.inp) {
						short_snaps = append(short_snaps, "i")
					} else {
						input_mode = false
					}
				} else {
					mch.mu.Unlock()
				}
			} else if ty == "ip" {

			} else if ty == "il" {
				long_snaps = append(long_snaps, line)
				short_snaps = append(short_snaps, line)
			} else if ty == "ir" {

			} else if ty == "ik" {
				if 2 <= len(tokens) {
					kg := tokens[1]
					if kg == "clear" {
						keyboard = []string{}
						all_keyboard = false
						short_snaps = append(short_snaps, line)
					} else if kg == "alphabet" || kg == "number" || kg == "space" || kg == "graphic" || kg == "cursor" || kg == "enter" || kg == "delete" || kg == "backspace" || kg == "escape" {
						if !all_keyboard && !slices.Contains(keyboard, kg) {
							keyboard = append(keyboard, kg)
							short_snaps = append(short_snaps, line)
						} else {
						}
					} else if kg == "all" {
						keyboard = []string{}
						all_keyboard = true
						short_snaps = append(short_snaps, line)
					}
				}
			} else if ty == "a" {

			} else if ty == "n" {
				saved_index = len(long_snaps)
				long_snaps = append(long_snaps, line)
				short_snaps = append(short_snaps, line)
			} else if ty == "f" {

			} else if ty == "c" {
				long_snaps = append(long_snaps, line)
				short_snaps = append(short_snaps, line)
			} else if ty == "p" {
				long_snaps = append(long_snaps, line)
				short_snaps = append(short_snaps, line)
			} else if ty == "l" {
				long_snaps = append(long_snaps, line)
				short_snaps = append(short_snaps, line)
			} else if ty == "la" {
				long_snaps = append(long_snaps, line)
				short_snaps = append(short_snaps, line)
			} else if ty == "t" {
				long_snaps = append(long_snaps, line)
				short_snaps = append(short_snaps, line)
			} else if ty == "tl" {
				long_snaps = append(long_snaps, line)
				short_snaps = append(short_snaps, line)
			} else if ty == "tr" {
				long_snaps = append(long_snaps, line)
				short_snaps = append(short_snaps, line)
			} else if ty == "b" {
				long_snaps = append(long_snaps, line)
				short_snaps = append(short_snaps, line)
			} else if ty == "o" {
				long_snaps = append(long_snaps, line)
				short_snaps = append(short_snaps, line)
			} else {
				if *verbose {
					log.Printf("unknown line: %s", line)
				}
			}
		case <-ticker.C:
			if ticker_flag == 0 {
				ticker_flag = 1
			} else if ticker_flag == 1 {
				ticker.Stop()
				ticker_flag = 2
				if 1 <= len(short_snaps) {
					if 1 <= len(conns) {
						message := strings.Join(short_snaps, "\n") + "\n"
						for _, conn := range conns {
							MyWriteMessage(conn, message)
						}
					}
					short_snaps = []string{}
				}
			}
		}
	}
}

func getChannel(ch_name string) *MyChannel {
	channels_mu.Lock()
	mch, ok := channels[ch_name]
	if !ok {
		if *verbose {
			fmt.Fprintf(os.Stderr, "New Channel %s\n", ch_name)
		}
		mch = &MyChannel{
			mu:  &sync.Mutex{},
			ch:  make(chan string, 1024),
			ins: []*websocket.Conn{},
			del: []*websocket.Conn{},
		}
		channels[ch_name] = mch
		go worker(mch, ch_name)
	}
	channels_mu.Unlock()
	return mch
}

func waitNever() {
	<-make(chan int)
}

func execConnect(ws_url string, ignore_tls bool) {
	var h http.Header = make(http.Header)
	if *user_password != "" {
		user_password_ := strings.Split(*user_password, ":")
		if 2 <= len(user_password_) {
			h.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user_password_[0]+":"+user_password_[1])))
		} else {
			h.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user_password_[0]+":"+user_password_[0])))
		}
	}
	dialer := *websocket.DefaultDialer
	if ignore_tls {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if strings.HasPrefix(ws_url, "http://") || strings.HasPrefix(ws_url, "https://") {
		ws_url = "ws" + ws_url[4:]
	}
	conn, _, err := dialer.Dial(ws_url, h)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can not connect ... %s %s\n", ws_url, err)
		return
	}
	fmt.Fprintf(os.Stderr, "http%s\n", ws_url[2:])
	in := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			in <- sc.Text()
		}
		in <- "exit"
	}()
	ticker := time.NewTicker(time.Millisecond * 10)
	ticker.Stop()
	ticker_flag := 2
	snaps := []string{"init"}
L:
	for {
		select {
		case line := <-in:
			if ticker_flag == 2 {
				ticker.Reset(time.Millisecond * 10)
			}
			ticker_flag = 0
			if *verbose {
				log.Printf("%s: %s", "", line)
			}
			if line == "exit" {
				break L
			}
			tokens := strings.Split(line, " ")
			if tokens[0] == "f" || tokens[0] == "i" {
				if tokens[0] == "i" {
					snaps = append(snaps, line)
				}
				if 1 <= len(snaps) {
					message := strings.Join(snaps, "\n") + "\n"
					MyWriteMessage(conn, message)
					snaps = []string{}
				}
				if tokens[0] == "i" {
					_, message, err := conn.ReadMessage()
					if err != nil {
						break L
					}
					fmt.Fprint(os.Stdout, string(message))
				}
			} else {
				snaps = append(snaps, line)
			}
		case <-ticker.C:
			if ticker_flag == 0 {
				ticker_flag = 1
			} else if ticker_flag == 1 {
				ticker.Stop()
				ticker_flag = 2
				if 1 <= len(snaps) {
					message := strings.Join(snaps, "\n") + "\n"
					MyWriteMessage(conn, message)
					snaps = []string{}
				}
			}
		}
	}
	if 1 <= len(snaps) {
		message := strings.Join(snaps, "\n") + "\n"
		MyWriteMessage(conn, message)
		snaps = []string{}
	}
}

var listenFailureFlag = false

func listen(url string, port int) {
	if *verbose {
		log.Printf("Listening on port %d", port)
	}
	var addr string
	if *public_listen {
		addr = fmt.Sprintf(":%d", port)
	} else {
		addr = fmt.Sprintf("127.0.0.1:%d", port)
	}
	fmt.Fprintf(os.Stderr, "%s\n", url)
	if *https_listen {
		if err := http.ListenAndServeTLS(addr, "tls.crt", "tls.key", nil); err != nil {
			listenFailureFlag = true
			log.Println("ListenAndServeTLS Error:", err)
		}
	} else {
		if err := http.ListenAndServe(addr, nil); err != nil {
			listenFailureFlag = true
			log.Println("ListenAndServe Error:", err)
		}
	}
}

//go:embed assets/vis.html
var vis_html []byte

//go:embed assets/favicon.ico
var favicon []byte

var user_password = flag.String("user", "", "<user:password>")

func unauth(w http.ResponseWriter) {
	w.Header().Add("WWW-Authenticate", `Basic realm="SECRET AREA"`)
	w.WriteHeader(http.StatusUnauthorized)
	http.Error(w, "Unauthorized", 401)
}
func makeRandomString(size int) string {
	alphabets := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	ret := ""
	for i := 0; i <= size; i++ {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabets))))
		k := int(j.Int64())
		if err != nil {
			k = 0
		}
		ret += alphabets[k : k+1]
	}
	return ret
}

func serve(port int) {
	channels = make(map[string]*MyChannel)
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Write(favicon)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if *user_password != "" {
			user, pass, ok := r.BasicAuth()
			if !ok {
				unauth(w)
				return
			}
			user_password_ := strings.Split(*user_password, ":")
			if 2 <= len(user_password_) {
				if user != user_password_[0] || pass != user_password_[1] {
					unauth(w)
					return
				}
			} else {
				if user != user_password_[0] || pass != user_password_[0] {
					unauth(w)
					return
				}
			}
		}
		ch_name := strings.Split(r.URL.Path, "/")[1]
		mch := getChannel(ch_name)
		if !websocket.IsWebSocketUpgrade(r) {
			w.Write(vis_html)
			return
		}
		upgrader := &websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		beforeMessage := ""
		for {
			_, message, err := ws.ReadMessage()
			if err != nil {
				break
			}
			if *verbose {
				log.Printf("%s>>> %s", ch_name, strings.ReplaceAll(strings.ReplaceAll(string(message), "\n", "\\n"), "\r", "\\r"))
			}
			lines := strings.Split(string(message), "\n")
			lines[0] = beforeMessage + lines[0]
			lines = lines[:len(lines)-1]
			if 1 <= len(lines) {
				for _, line := range lines {
					if *verbose {
						log.Printf("%s: %s", ch_name, line)
					}
					tokens := strings.Split(line, " ")
					if tokens[0] == "register" {
						mch.mu.Lock()
						mch.ins = append(mch.ins, ws)
						mch.mu.Unlock()
					} else if tokens[0] == "i" {
						mch.mu.Lock()
						mch.inp = append(mch.inp, ws)
						mch.mu.Unlock()
					}
					mch.ch <- line
				}
				mch.ch <- "flush"
			}
		}
		mch.mu.Lock()
		mch.del = append(mch.del, ws)
		mch.mu.Unlock()
		mch.ch <- "unregister"
		if *verbose {
			log.Printf("%s: unregister", ch_name)
		}
		ws.Close()
	})
	http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("./js"))))
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("./css"))))
	secret1 := makeRandomString(16)
	secret2 := makeRandomString(16)
	http.HandleFunc("/secret-"+secret1, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(secret2))
	})
	url := ""
	if *https_listen {
		url = fmt.Sprintf("https://localhost:%d/", port)
	} else {
		url = fmt.Sprintf("http://localhost:%d/", port)
	}
	go listen(url, port)
	for {
		if listenFailureFlag {
			execConnect(url+secret2, true)
			return
		}
		res, err := http.Get(url + "secret-" + secret1)
		if err != nil {
			continue
		}
		buf := make([]byte, len(secret2))
		res.Body.Read(buf)
		if string(buf) == secret2 {
			break
		} else {
			listenFailureFlag = true
			continue
		}
	}
	mch := getChannel("")
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := sc.Text()
		if *verbose {
			log.Printf("%s: %s", "", line)
		}
		tokens := strings.Split(line, " ")
		if tokens[0] == "i" {
			mch.mu.Lock()
			mch.inp = append(mch.inp, nil)
			mch.mu.Unlock()
		}
		mch.ch <- line
	}
	mch.ch <- "flush"
	waitNever()
}
func main() {
	var (
		port       = flag.Int("port", 8080, "http server port")
		connect    = flag.String("connect", "", "connect ws or wss url")
		ignore_tls = flag.Bool("ignore-tls", false, "ignore tls")
	)
	flag.Parse()
	if *connect != "" {
		execConnect(*connect, *ignore_tls)
	} else {
		serve(*port)
	}
}
