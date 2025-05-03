include .env

# 変数は.envに定義されているものを使用する
# 証明書を取得または更新するコマンド
.PHONY: create-rsa-cert
create-rsa-cert:
	sudo certbot certonly --manual \
		--server https://acme-v02.api.letsencrypt.org/directory \
		--preferred-challenges dns \
		-m ${EMAIL} \
		-d ${DOMAIN} \
		--agree-tos \
		--key-type rsa \
		--rsa-key-size ${KEY_SIZE} \
		--deploy-hook "./script.sh"

# ecdsaの証明書を作成または更新するコマンド
.PHONY: create-ecdsa-cert
create-ecdsa-cert:
	sudo certbot certonly --manual \
		--server https://acme-v02.api.letsencrypt.org/directory \
		--preferred-challenges dns \
		-m ${EMAIL} \
		-d ${DOMAIN} \
		--agree-tos \
		--key-type ecdsa \
		--elliptic-curve ${ELLIPTIC_CURVE} \
		--deploy-hook "./script.sh"

# rsaマルチドメイン証明書を作成または更新するコマンド
.PHONY: create-multi-rsa-cert
create-multi-rsa-cert:
	sudo certbot certonly --manual \
		--server https://acme-v02.api.letsencrypt.org/directory \
		--preferred-challenges dns \
		-m ${EMAIL} \
		-d ${MULTI_DOMAIN1} \
		-d ${MULTI_DOMAIN2} \
		-d ${MULTI_DOMAIN3} \
		--agree-tos \
		--key-type ${KEY_TYPE} \
		--rsa-key-size ${KEY_SIZE} \
		--deploy-hook "./script.sh"

# ecdsaマルチドメイン証明書を作成または更新するコマンド
.PHONY: create-multi-ecdsa-cert
create-multi-ecdsa-cert:
	sudo certbot certonly --manual \
		--server https://acme-v02.api.letsencrypt.org/directory \
		--preferred-challenges dns \
		-m ${EMAIL} \
		-d ${MULTI_DOMAIN1} \
		-d ${MULTI_DOMAIN2} \
		-d ${MULTI_DOMAIN3} \
		--agree-tos \
		--key-type ecdsa \
		--elliptic-curve ${ELLIPTIC_CURVE} \
		--deploy-hook "./script.sh"
