バージョン情報
==============


2024-02-20
----------

* 標準入力が切れても終了しないように変更
  * .gvファイルをパイプで入れたときに、ブラウザで見る暇がなく終了していたため
* ポートがふさがれていた場合、自動的にlocalhostの同ポートへ接続して動作するように変更
  * この場合は標準入力が切れると即座に終了
    * サーバーが別プロセスのため、即座に終了してもブラウザで見れるため
* 自動フラッシュ周りを強化
* ページ切替機能を実装
* .gvファイルのダウンロード機能の実装
* .gvファイルのアップロード機能の実装
* .gvファイルのダウンロード→別チャンネル→.gvファイルのアップロードの手順で出来るようになったことを、コピー機能として実装
* notranslateタグを追加

2024-02-05
----------

GitHub初公開版。
