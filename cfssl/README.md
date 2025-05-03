## CFSSL

cfsslを使用して証明書を作成するためのスクリプトです。

(cfssl)[https://github.com/cloudflare/cfssl]

### インストール

```bash
brew install cfssl
```

### コマンドを実行する

`Makefile`によく使用するコマンドを定義しています。

自己証明書の作成順序は以下のようになります。

1. CA証明書の作成
2. 中間CA証明書の作成
3. 中間CA証明書の署名
4. サーバ証明書の作成