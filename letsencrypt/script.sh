#!/bin/bash

echo "Starting Let's Encrypt script..."

# .env ファイルを読み込む
if [ -f .env ]; then
    source .env
else
    echo ".env file not found. Exiting."
    exit 1
fi

# 証明書の保存先ディレクトリ
TARGET_DIR=$(dirname $(pwd))/certificates/$DOMAIN

# 保存先ディレクトリが存在しない場合は作成
mkdir -p "$TARGET_DIR"

# ドメイン名を取得
DOMAIN=$DOMAIN

# 証明書をコピー
cp "/private/etc/letsencrypt/live/$DOMAIN/cert.pem" "$TARGET_DIR/cert.pem"
cp "/private/etc/letsencrypt/live/$DOMAIN/chain.pem" "$TARGET_DIR/chain.pem"
cp "/private/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$TARGET_DIR/privkey.pem"

echo "Certificates have been copied to $TARGET_DIR"