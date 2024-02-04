package main

import (
	"bufio"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

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
	for {
		line := <-mch.ch
		if *verbose {
			log.Printf("%s(%d): %s", ch_name, len(conns), line)
		}
		tokens := strings.Split(line, " ")
		ty := tokens[0]
		if ty == "register" {
			mch.mu.Lock()
			if 1 <= len(mch.ins) {
				var message string
				if 1 <= len(long_snaps) {
					message += strings.Join(long_snaps, "\n") + "\n"
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
		} else if ty == "flush" || ty == "f" {
			if 1 <= len(conns) && 1 <= len(short_snaps) {
				message := strings.Join(short_snaps, "\n") + "\n"
				for _, conn := range conns {
					MyWriteMessage(conn, message)
				}
			}
			short_snaps = []string{}
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
		} else if ty == "i" {
			if !input_mode {
				input_mode = true
				short_snaps = append(short_snaps, "i")
			}
		} else if ty == "k" {
			mch.mu.Lock()
			if 1 <= len(mch.inp) {
				ws := mch.inp[0]
				mch.inp = mch.inp[1:]
				mch.mu.Unlock()
				if ws == nil {
					fmt.Println(line)
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
	}
}

func getChannel(ch_name string) *MyChannel {
	channels_mu.Lock()
	mch, ok := channels[ch_name]
	if !ok {
		if *verbose {
			fmt.Printf("New Channel %s\n", ch_name)
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

func listen(port int) {
	if *verbose {
		log.Printf("Listening on port %d", port)
	}
	var addr string
	if *public_listen {
		addr = fmt.Sprintf(":%d", port)
	} else {
		addr = fmt.Sprintf("127.0.0.1:%d", port)
	}
	if *https_listen {
		fmt.Fprintf(os.Stderr, "https://localhost:%d/\n", port)
		if err := http.ListenAndServeTLS(fmt.Sprintf("127.0.0.1:%d", port), "tls.crt", "tls.key", nil); err != nil {
			log.Panicln("ListenAndServe Error:", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "http://localhost:%d/\n", port)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Panicln("ListenAndServe Error:", err)
		}
	}
}

//go:embed assets/vis.html
var vis_html []byte

var user_password = flag.String("user", "", "<user:password>")

func unauth(w http.ResponseWriter) {
	w.Header().Add("WWW-Authenticate", `Basic realm="SECRET AREA"`)
	w.WriteHeader(http.StatusUnauthorized)
	http.Error(w, "Unauthorized", 401)
}

func serve(port int) {
	channels = make(map[string]*MyChannel)
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
	go listen(port)
	mch := getChannel("")
	sc := bufio.NewScanner(os.Stdin)
	for {
		sc.Scan()
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
}

func main() {
	var (
		port       = flag.Int("port", 8080, "http server port")
		connect    = flag.String("connect", "", "connect ws or wss url")
		ignore_tls = flag.Bool("ignore-tls", false, "ignore tls")
	)
	flag.Parse()
	if *connect != "" {
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
		if *ignore_tls {
			dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		conn, _, err := dialer.Dial(*connect, h)
		if err != nil {
			fmt.Printf("Can not connect ... %s\n", *connect)
			return
		}
		sc := bufio.NewScanner(os.Stdin)
		snaps := []string{}
		for {
			sc.Scan()
			line := sc.Text()
			if *verbose {
				log.Printf("%s: %s", "", line)
			}
			tokens := strings.Split(line, " ")
			if tokens[0] == "f" {
				message := strings.Join(snaps, "\n") + "\n"
				MyWriteMessage(conn, message)
				snaps = []string{}
			} else {
				snaps = append(snaps, line)
			}
		}
	} else {
		serve(*port)
	}
}
