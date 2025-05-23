#!/usr/bin/env node

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

// メイン関数
function main(): void {
	// 引数が渡されているか確認
	if (process.argv.length < 3) {
		console.log("Usage: node verify-cert.ts <DOMAIN>");
		return;
	}

	// ドメイン名を取得
	const domain: string = process.argv[2];
	console.log(`Verifying certificate for domain: ${domain}`);

	// fqdn を宣言して値を代入
	const fqdn: string = domain;
	const localPath: string = "../certificates/";

	// ファイルパスを指定
	const certFile: string = path.join(localPath, fqdn, "cert.pem"); // サーバー証明書
	const chainFile: string = path.join(localPath, fqdn, "chain.pem"); // 中間証明書
	const keyFile: string = path.join(localPath, fqdn, "privkey.pem"); // サーバー証明書の秘密鍵

	// 証明書と鍵を読み込む
	const serverCert = loadCertificate(certFile);
	const intermediateCert = loadCertificate(chainFile);
	const privateKey = loadPrivateKey(keyFile);

	// サーバー証明書の詳細を表示
	displayServerDetails(serverCert);
	// 中間証明書の詳細を表示
	displayIntermediateDetails(intermediateCert);

	// サーバー証明書と中間証明書の整合性を確認
	try {
		verifySignature(serverCert, intermediateCert);
		console.log("サーバー証明書と中間証明書の整合性が確認されました");
	} catch (err: unknown) {
		if (err instanceof Error) {
			console.error(
				`サーバー証明書と中間証明書の整合性が確認できません: ${err.message}`,
			);
		} else {
			console.error(
				`サーバー証明書と中間証明書の整合性が確認できません: ${String(err)}`,
			);
		}
		process.exit(1);
	}

	// サーバー証明書と秘密鍵の整合性を確認
	try {
		verifyKeyPair(serverCert, privateKey);
		console.log("サーバー証明書と秘密鍵の整合性が確認されました");
	} catch (err: unknown) {
		if (err instanceof Error) {
			console.error(
				`サーバー証明書と秘密鍵の整合性が確認できません: ${err.message}`,
			);
		} else {
			console.error(
				`サーバー証明書と秘密鍵の整合性が確認できません: ${String(err)}`,
			);
		}
		process.exit(1);
	}
}

// 証明書を読み込む関数
function loadCertificate(filePath: string): crypto.X509Certificate {
	try {
		const data = fs.readFileSync(filePath, "utf8");
		const cert = new crypto.X509Certificate(data);
		return cert;
	} catch (err: unknown) {
		if (err instanceof Error) {
			console.error(`証明書の読み込みに失敗しました: ${err.message}`);
		} else {
			console.error(`証明書の読み込みに失敗しました: ${String(err)}`);
		}
		process.exit(1);
	}
}

// 秘密鍵を読み込む関数
function loadPrivateKey(filePath: string): crypto.KeyObject {
	try {
		const data = fs.readFileSync(filePath, "utf8");
		return crypto.createPrivateKey(data);
	} catch (err: unknown) {
		if (err instanceof Error) {
			console.error(`秘密鍵の読み込みに失敗しました: ${err.message}`);
		} else {
			console.error(`秘密鍵の読み込みに失敗しました: ${String(err)}`);
		}
		process.exit(1);
	}
}

// サーバー証明書の詳細を表示する関数
function displayServerDetails(cert: crypto.X509Certificate): void {
	console.log("サーバー証明書の詳細:");
	console.log(`有効期限: ${cert.validTo}`);
	console.log(`発行者: ${cert.issuer}`);
	console.log(`コモンネーム: ${getCommonName(cert.subject)}`);
	console.log(`SANs: ${cert.subjectAltName || "[]"}`);
	// @ts-ignore
	console.log(`パブリックキー情報: ${cert.publicKey.asymmetricKeyType}`);
	// @ts-ignore
	console.log(`署名アルゴリズム: ${cert.sigalg}`);
	// Node.jsの標準ライブラリではKeyUsageとExtKeyUsageの詳細表示は制限があります
}

// 中間証明書の詳細を表示する関数
function displayIntermediateDetails(cert: crypto.X509Certificate): void {
	console.log("中間証明書の詳細:");
	console.log(`有効期限: ${cert.validTo}`);
	console.log(`発行者: ${cert.issuer}`);
	console.log(`コモンネーム: ${getCommonName(cert.subject)}`);
	console.log(`サブジェクト: ${cert.subject}`);
	console.log(`SANs: ${cert.subjectAltName || "[]"}`);
	// @ts-ignore
	console.log(`パブリックキー情報: ${cert.publicKey.asymmetricKeyType}`);
	// @ts-ignore
	console.log(`署名アルゴリズム: ${cert.sigalg}`);
	// Node.jsの標準ライブラリではKeyUsageとExtKeyUsageの詳細表示は制限があります
}

// サブジェクトからコモンネームを抽出する関数
function getCommonName(subject: string): string {
	const cnMatch = subject.match(/CN=([^,]+)/);
	return cnMatch ? cnMatch[1] : "N/A";
}

// サーバー証明書と中間証明書の整合性を確認する関数
function verifySignature(
	serverCert: crypto.X509Certificate,
	intermediateCert: crypto.X509Certificate,
): void {
	// @ts-ignore
	const verified = serverCert.verify(intermediateCert.publicKey);
	if (!verified) {
		throw new Error("署名の検証に失敗しました");
	}
}

// サーバー証明書と秘密鍵の整合性を確認する関数
function verifyKeyPair(
	cert: crypto.X509Certificate,
	privateKey: crypto.KeyObject,
): void {
	// @ts-ignore
	const publicKey = cert.publicKey;
	const testData = Buffer.from("test");
	try {
		const signature = crypto.sign("sha256", testData, privateKey);
		const verified = crypto.verify("sha256", testData, publicKey, signature);
		if (!verified) {
			throw new Error("鍵ペアの検証に失敗しました");
		}
	} catch (err: unknown) {
		if (err instanceof Error) {
			throw new Error(`鍵ペアの検証中にエラーが発生しました: ${err.message}`);
		}
		throw new Error(`鍵ペアの検証中にエラーが発生しました: ${String(err)}`);
	}
}

// メイン関数を実行
main();
