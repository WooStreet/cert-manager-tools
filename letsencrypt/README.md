## letsencrypt

certbotを使用してlet's encryptを作成するコマンドがあります。作成された証明書はcertificatesディレクトリに保存されるようになっています。

### 環境設定

certbotのインストールを行います。

```bash
brew install certbot
```

letsencrypt配下に`.env`ファイルを作成して以下のように記述してください。

```env
DOMAIN=
KEY_SIZE=
EMAIL=
ELLIPTIC_CURVE=
MULTI_DOMAIN1=
MULTI_DOMAIN2=
MULTI_DOMAIN3=
```

### コマンドの実行


`Makefile`によく使用するコマンドを定義しています。

例えば、rsaの証明書を作成する場合は以下のように実行します。

```bash
make create-rsa-cert
```

