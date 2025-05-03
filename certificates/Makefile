# サーバー証明書をコピー
# make cp-cert DOMAIN=example.com
cp-cert:
	cat ${DOMAIN}/cert.pem | pbcopy
	
# 秘密鍵をコピー
# make cp-privkey DOMAIN=example.com
.PHONY: cp-privkey
cp-privkey:
	sudo cat ${DOMAIN}/privkey.pem | pbcopy

# 中間CA局証明書をコピー
# make cp-chain DOMAIN=example.com
.PHONY: cp-chain
cp-chain:
	cat ${DOMAIN}/chain.pem | pbcopy

# 証明書を圧縮
# make zip-cert DOMAIN=example.com
.PHONY: zip-cert
zip-cert:
	 sudo zip -e ${DOMAIN}.zip *

# 証明書パスワード password
# make zip-password-cert DOMAIN=example.com
.PHONY: zip-password-cert
zip-password-cert:
	sudo zip -r -e ${DOMAIN}.zip certs