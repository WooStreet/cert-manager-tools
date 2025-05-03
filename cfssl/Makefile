# csrとcaの雛形を作成
# make create-csr-ca DOMAIN=example.net
.PHONY: create-csr-ca
create-csr-ca:
	mkdir -p ../certificates/${DOMAIN}
	cfssl print-defaults config > ../certificates/${DOMAIN}/ca-config.json
	cfssl print-defaults csr > ../certificates/${DOMAIN}/ca-csr.json

# 一気に作成する場合
# make create-all DOMAIN=example.net
.PHONY: create-all
create-all:
	make create-cert-authority DOMAIN=${DOMAIN}
	make create-intermediate-ca DOMAIN=${DOMAIN}
	make sign-intermediate-ca DOMAIN=${DOMAIN}
	make create-cert-pem DOMAIN=${DOMAIN}

# ルートCAの証明書と秘密鍵を生成
# make create-cert-authority DOMAIN=example.net
.PHONY: create-cert-authority
create-cert-authority:
	mkdir -p ../certificates/${DOMAIN}
	cfssl gencert -initca \
	./ca-csr.json | \
	cfssljson -bare ../certificates/${DOMAIN}/ca

# 中間CA証明書の作成 
# make create-intermediate-ca DOMAIN=example.net
.PHONY: create-intermediate-ca
create-intermediate-ca:
	mkdir -p ../certificates/${DOMAIN}
	cfssl gencert \
	-ca ../certificates/${DOMAIN}/ca.pem \
	-ca-key ../certificates/${DOMAIN}/ca-key.pem \
	-config ./ca-config.json \
	-profile intermediate ./intermediate-csr.json | \
	cfssljson -bare ../certificates/${DOMAIN}/chain

# 中間CAをルートCAで署名
# make sign-intermediate-ca DOMAIN=example.net
.PHONY: sign-intermediate-ca
sign-intermediate-ca:
	mkdir -p ../certificates/${DOMAIN}
	cfssl sign \
	-ca ../certificates/${DOMAIN}/ca.pem \
	-ca-key ../certificates/${DOMAIN}/ca-key.pem \
	-config ./ca-config.json \
	-profile intermediate ../certificates/${DOMAIN}/chain.csr | \
	cfssljson -bare ../certificates/${DOMAIN}/chain

# サーバー証明書の作成
# make create-cert-pem DOMAIN=example.net
.PHONY: create-cert-pem
create-cert-pem:
	mkdir -p ../certificates/${DOMAIN}
	cfssl gencert \
	-ca ../certificates/${DOMAIN}/chain.pem \
	-ca-key ../certificates/${DOMAIN}/chain-key.pem \
	-config ./ca-config.json \
	-profile server ./server-csr.json | \
	cfssljson -bare ../certificates/${DOMAIN}/cert
	mv ../certificates/${DOMAIN}/cert-key.pem ../certificates/${DOMAIN}/privkey.pem
