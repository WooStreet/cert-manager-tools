package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
)


func main() {
	// 引数が渡されているか確認
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run verify-cert.go <DOMAIN>")
		return
	}

	// ドメイン名を取得
	domain := os.Args[1]
	fmt.Printf("Verifying certificate for domain: %s\n", domain)

	// fqdn を宣言して値を代入
	fqdn := domain
	localPath := "../certificates/"

	// ファイルパスを指定
	certFile := filepath.Join(localPath, fqdn, "cert.pem")  // サーバー証明書
	chainFile := filepath.Join(localPath, fqdn, "chain.pem") // 中間証明書
	keyFile := filepath.Join(localPath, fqdn, "privkey.pem") // サーバー証明書の秘密鍵

	// サーバー証明書を読み込む
	serverCert := loadCertificate(certFile)
	// 中間証明書を読み込む
	intermediateCert := loadCertificate(chainFile)
	// 秘密鍵を読み込む
	privateKey := loadPrivateKey(keyFile)

	// サーバー証明書の詳細を表示
	displayServerDetails(serverCert)
	// 中間証明書の詳細を表示
	displayIntermediateDetails(intermediateCert)


	// サーバー証明書と中間証明書の整合性を確認
	err := serverCert.CheckSignatureFrom(intermediateCert)
	if err != nil {
			log.Fatalf("サーバー証明書と中間証明書の整合性が確認できません: %v", err)
	}
	fmt.Println("サーバー証明書と中間証明書の整合性が確認されました")

	// サーバー証明書と秘密鍵の整合性を確認
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
			// RSAの場合
			if rsaPub, ok := serverCert.PublicKey.(*rsa.PublicKey); ok {
					if rsaPub.N.Cmp(key.PublicKey.N) != 0 {
							log.Fatalf("サーバー証明書とRSA秘密鍵の整合性が確認できません")
					}
			} else {
					log.Fatalf("サーバー証明書の公開鍵がRSA形式ではありません")
			}
	case *ecdsa.PrivateKey:
			// ECDSAの場合
			if ecdsaPub, ok := serverCert.PublicKey.(*ecdsa.PublicKey); ok {
					if ecdsaPub.X.Cmp(key.PublicKey.X) != 0 || ecdsaPub.Y.Cmp(key.PublicKey.Y) != 0 {
							log.Fatalf("サーバー証明書とECDSA秘密鍵の整合性が確認できません")
					}
			} else {
					log.Fatalf("サーバー証明書の公開鍵がECDSA形式ではありません")
			}
	default:
			log.Fatalf("未知の秘密鍵形式です")
	}

	fmt.Println("サーバー証明書と秘密鍵の整合性が確認されました")
}

// 証明書を読み込む関数
func loadCertificate(filePath string) *x509.Certificate {
	data, err := os.ReadFile(filePath)
	if err != nil {
			log.Fatalf("ファイルの読み込みに失敗しました: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
			log.Fatalf("PEMデータのデコードに失敗しました: %s", filePath)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
			log.Fatalf("証明書のパースに失敗しました: %v", err)
	}

	return cert
}

// 秘密鍵を読み込む関数
func loadPrivateKey(filePath string) interface{} {
	data, err := os.ReadFile(filePath)
	if err != nil {
			log.Fatalf("ファイルの読み込みに失敗しました: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
			log.Fatalf("PEMデータのデコードに失敗しました: %s", filePath)
	}

	// PKCS#1, PKCS#8, EC形式の秘密鍵に対応
	var key interface{}
	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
			// PKCS#8 の場合
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
					// EC形式の場合
					key, err = x509.ParseECPrivateKey(block.Bytes)
					if err != nil {
							log.Fatalf("秘密鍵のパースに失敗しました: %v", err)
					}
			}
	}
	return key
}

// サーバー証明書の詳細を表示する関数
func displayServerDetails(cert *x509.Certificate) {
	fmt.Printf("サーバー証明書の詳細:\n")
	fmt.Printf("有効期限: %s\n", cert.NotAfter)
	fmt.Printf("発行者: %s\n", cert.Issuer)
	fmt.Printf("コモンネーム: %s\n", cert.Subject.CommonName)
	fmt.Printf(("SANs: %s\n"), cert.DNSNames)
	fmt.Printf("パブリックキー情報: %s\n", cert.PublicKeyAlgorithm)
	fmt.Printf("署名アルゴリズム: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("Key Usage: %s\n", keyUsageToString(cert.KeyUsage))
	fmt.Printf("Extended Key Usage: %s\n", extKeyUsageToString(cert.ExtKeyUsage))
}
// 中間証明書の詳細を表示する関数
func displayIntermediateDetails(cert *x509.Certificate) {
	fmt.Printf("中間証明書の詳細:\n")
	fmt.Printf("有効期限: %s\n", cert.NotAfter)
	fmt.Printf("発行者: %s\n", cert.Issuer)
	fmt.Printf("コモンネーム: %s\n", cert.Subject.CommonName)
	fmt.Printf("サブジェクト: %s\n", cert.Subject)
	fmt.Printf(("SANs: %s\n"), cert.DNSNames)
	fmt.Printf("パブリックキー情報: %s\n", cert.PublicKeyAlgorithm)
	fmt.Printf("署名アルゴリズム: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("Key Usage: %s\n", keyUsageToString(cert.KeyUsage))
	fmt.Printf("Extended Key Usage: %s\n", extKeyUsageToString(cert.ExtKeyUsage))
}

// KeyUsage を文字列に変換する関数
func keyUsageToString(ku x509.KeyUsage) string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
			usages = append(usages, "DigitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
			usages = append(usages, "ContentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
			usages = append(usages, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
			usages = append(usages, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
			usages = append(usages, "KeyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
			usages = append(usages, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
			usages = append(usages, "CRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
			usages = append(usages, "EncipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
			usages = append(usages, "DecipherOnly")
	}
	return fmt.Sprintf("[%s]", stringJoin(usages, ", "))
}
// ExtKeyUsage を文字列に変換する関数
func extKeyUsageToString(extUsages []x509.ExtKeyUsage) string {
	var usages []string
	for _, usage := range extUsages {
			switch usage {
			case x509.ExtKeyUsageAny:
					usages = append(usages, "Any")
			case x509.ExtKeyUsageServerAuth:
					usages = append(usages, "ServerAuth")
			case x509.ExtKeyUsageClientAuth:
					usages = append(usages, "ClientAuth")
			case x509.ExtKeyUsageCodeSigning:
					usages = append(usages, "CodeSigning")
			case x509.ExtKeyUsageEmailProtection:
					usages = append(usages, "EmailProtection")
			case x509.ExtKeyUsageIPSECEndSystem:
					usages = append(usages, "IPSECEndSystem")
			case x509.ExtKeyUsageIPSECTunnel:
					usages = append(usages, "IPSECTunnel")
			case x509.ExtKeyUsageIPSECUser:
					usages = append(usages, "IPSECUser")
			case x509.ExtKeyUsageTimeStamping:
					usages = append(usages, "TimeStamping")
			case x509.ExtKeyUsageOCSPSigning:
					usages = append(usages, "OCSPSigning")
			case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
					usages = append(usages, "MicrosoftServerGatedCrypto")
			case x509.ExtKeyUsageNetscapeServerGatedCrypto:
					usages = append(usages, "NetscapeServerGatedCrypto")
			default:
					usages = append(usages, "Unknown")
			}
	}
	return fmt.Sprintf("[%s]", stringJoin(usages, ", "))
}

// スライスをカンマ区切りの文字列に変換するヘルパー関数
func stringJoin(elements []string, sep string) string {
	result := ""
	for i, elem := range elements {
			if i > 0 {
					result += sep
			}
			result += elem
	}
	return result
}