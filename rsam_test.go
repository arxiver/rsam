package rsam_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/gossl/rsam"
)

func TestPublicKeySignature(t *testing.T) {
	priv, pub, err := rsam.GeneratePairKeys(1024)
	if err != nil {
		t.Error(err)
	}
	signature, err := rsam.SignWithPublicKey([]byte("test"), pub)
	if err != nil {
		t.Error(err)
	}
	err = rsam.VerifyWithPrivateKey([]byte("test"), signature, priv)
	if err != nil {
		t.Error(err)
	}
}

func TestPrivateKeySignature(t *testing.T) {
	priv, pub, err := rsam.GeneratePairKeys(1024)
	if err != nil {
		t.Error()
	}
	signature, err := rsam.SignWithPrivateKey([]byte("test"), priv)
	if err != nil {
		t.Error()
	}
	err = rsam.VerifyWithPublicKey([]byte("test"), signature, pub)
	if err != nil {
		t.Error()
	}
}

func TestGeneratePairKeys(t *testing.T) {
	priv, pub, err := rsam.GeneratePairKeys(1024)
	if err != nil {
		t.Error(err)
	}
	if priv == nil || pub == nil {
		t.Error("keys are nil")
	}
}

func TestPublicKeyEncryption(t *testing.T) {
	priv, pub, _ := rsam.GeneratePairKeys(2048)
	msg := []byte("hello world")
	encrypted, err := rsam.EncryptWithPublicKey(msg, pub, sha256.New())
	if err != nil {
		t.Error(err)
	}
	decrypted, err := rsam.DecryptWithPrivateKey(encrypted, priv, sha256.New())
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(msg, decrypted) {
		t.Error("decrypted message not equal to original message")
	}
}

func TestPublicKeyEncryptionLongMessage(t *testing.T) {
	priv, pub, _ := rsam.GeneratePairKeys(2048)
	rep := 1000
	msg := []byte("hello world")
	for i := 0; i < rep; i++ {
		msg = append(msg, []byte("hello world")...)
	}
	encrypted, err := rsam.EncryptWithPublicKey(msg, pub, sha256.New())
	if err != nil {
		t.Error(err)
	}
	decrypted, err := rsam.DecryptWithPrivateKey(encrypted, priv, sha256.New())
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(msg, decrypted) {
		t.Error("decrypted message not equal to original message")
	}
}

/*
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQD1/618vsRezcClpPzD4fbusyH63UiM/ZT7qzNtCIvyqW0xSzDH
0t1/dmjQH4mOaiel2jQT9fQnSBKmGuG5GZ2ueDRgqrLZd3resJix9V3Q9tvSxevP
svOiSlV3Z8QXTMTMSQBA1DNpSDsi8inupoJSUUiZ+8k8d3eMJ2gBIgZ5qQIDAQAB
AoGAEYKunbeSkNECiofw+hyGkD0uCQZhWK/gP/3SvksicxZ+UEjy4vZuj9kk4tOr
3fhOdC7REC6sv3MQ6MP3F07se1AV8xbvz5Y6HtwgNNMFNMXgPCKdWlpkAo4ukkWa
5ZPJJOsVp8uvNmGBCUl9nRGIPv8kfjxqyVrQjzCNYqK/oNECQQD/IfsS4xathdhv
gUR1dARvWJsyIRCSJ/hgl8A1sEus40NfB0nRgE0r9Om4d9/20sfixUgZfn+Wm3uM
RSoBMGC1AkEA9tW/mNwUVWo8g4sqX3q9YP0ZBOvIvuAivbkUwDLmiBRr+zoqPyxi
QivW23pFnCHf9pSV04djnaPs/CBqWu+xpQJAQWnR+Na2gsj1ZClthvu3A2FhcSnf
GMocuY9O3bUUwgAGzv+MYqWVo7aIkh5SEvOaAj94q+iuB8xXkfBNw75GnQJBAOx6
PdQxzN1EKXORKWhODA9Wi9i2GB4eV8pR/fphCZGHlygaQo1BdWWV4INm8jeyEIKJ
Ob1tMVe+y/WFDL/Qce0CQGlcpslM+aHg0rwf7LYOjlvS+fwb+F1s6VfGLnXqAQmG
WNySVkTY3ZHgkt8v8FM6LhJLbDDKpMGvSroXoSLGF3k=
-----END RSA PRIVATE KEY-----


-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD1/618vsRezcClpPzD4fbusyH6
3UiM/ZT7qzNtCIvyqW0xSzDH0t1/dmjQH4mOaiel2jQT9fQnSBKmGuG5GZ2ueDRg
qrLZd3resJix9V3Q9tvSxevPsvOiSlV3Z8QXTMTMSQBA1DNpSDsi8inupoJSUUiZ
+8k8d3eMJ2gBIgZ5qQIDAQAB
-----END PUBLIC KEY-----
*/
