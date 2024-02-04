# General Visualizer Hub

GV（General Visualizer）は、プログラミングコンテストなどで手軽にゲーム状況を把握するために作られた、汎用的なビジュアライザを実現するためのプロトコルです。

本リポジトリでは、GVに対応したhttp(およびWebSocket)からなるハブと、そのハブ上で動くJavaScript版のクライアントソフトを提供しています。

なお、 General Visualizer Client ( https://github.com/colun/gvc ) とは姉妹関係にありますが、連携して動くことはありません。
単に同じプロトコルを使っているだけです。
General Visualizer Hub は、単独で動くことに注意してください。

# インストール方法

Go言語のインストールと、GOBINの設定を事前に行っておく必要があります。
そのうえで、下記コマンドを実行します。

> go install gvh.go

# 起動方法

インストール後に

> gvh

で起動します。

コンソール入力にはそのままGV命令を書き込むことが可能です。
ローカルで動かす場合はこれで十分だと思います。

表示されたURLにアクセスすると、GVに書き込まれた命令によるビジュアライズがブラウザに表示されます。

# 公開モードでの起動

サーバーでgvhを起動する場合、外部からもアクセス可能にする必要があります。
そういった際は、

> gvh -public

というように、 -public オプションを付けることでローカル以外からもアクセス可能になります。

# 接続

公開されているサーバーに接続してGV命令を書き込んでいくことが可能です。

> gvh -connect ws://localhost:8080/

のようにすることで、接続できます。

# httpsでの起動について

tls.crt と tls.key を同じフォルダに置く必要があります。
一人で実験などで使う場合には、オレオレ証明書などでも十分かもしれません。

オレオレ証明書（ですらないかもしれないもの）は、たとえば以下のように発行できます。

> openssl genrsa -out tls.key 2048
> openssl req -new -x509 -sha256 -key tls.key -subj "/C=JP/ST=Fukuoka/O=GVH" -out tls.crt -days 3650

証明書が用意できたら、

> gvh -https

で、httpsで起動可能です。

接続の際、ちゃんとした証明書を使っている場合は不要ですが、オレオレ証明書のような場合には -ignore-tls のようにオプションを付ける必要があります。

> gvh -connect wss://localhost:8080/ -ignore-tls

# プロトコルについて

https://github.com/colun/gvc

に準じます。

ただし、l命令だけは

l X1 Y1 X2 Y2 COLOR [RADIUS]

とし、RADIUSの省略値を0.05とします。
RADIUSはWIDTHと言い換えた方が理解しやすいかもしれませんが、
線の幅の直径ではなく半径を示している点に注意が必要です。

なお、将来的に General Visualizer Client の方でもl命令へとRADIUSを追加する予定があります。

現在対応している命令は、以下になります。

- n命令
- c命令
- t命令
- tl命令
- tr命令
- l命令
- p命令
- o命令
- f命令
- r命令
- ra命令
- i命令
- il命令

ただし、複数のn命令のページ切替には現段階では対応していません。
将来的に対応の予定があります。
