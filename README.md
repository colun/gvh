# General Visualizer Hub

GV（General Visualizer）は、プログラミングコンテストなどで手軽にゲーム状況を把握するために作られた、汎用的なビジュアライザを実現するためのプロトコルです。

本リポジトリでは、GVに対応したhttp(およびWebSocket)からなるハブと、そのハブ上で動くJavaScript版のクライアントソフトを提供しています。

なお、 General Visualizer Client ( https://github.com/colun/gvc ) とは姉妹関係にありますが、連携して動くことはありません。
単に同じプロトコルを使っているだけです。
General Visualizer Hub は、単独で動くことに注意してください。

# インストール方法

go install gvh.go

# 起動方法

インストール後に

gvh

で起動します。

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
