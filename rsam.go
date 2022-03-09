package rsam

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"

	"github.com/gossl/rsam/cry"
)

// Generates a new key pair (private and public)
func GeneratePairKeys(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privkey, &privkey.PublicKey, nil
}

// Converts private key to bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

// Converts public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes
}

// Converts bytes to private key
func BytesToPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Converts bytes to public key
func BytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, err
	}
	return key, nil
}

// Encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// Decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Encrypts data with public key
func EncryptWithPrivateKey(msg []byte, priv *rsa.PrivateKey) ([]byte, error) {
	return nil, nil
}

// Decrypts data with private key
func DecryptWithPublicKey(ciphertext []byte, pub *rsa.PublicKey) ([]byte, error) {
	return nil, nil
}

// Decrypts data with private key
func SignWithPrivateKey(msg []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := crypto.Hash(crypto.SHA512)
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, hash, msg)
	cry.SignPKCS1v15(rand.Reader, priv, hash, msg)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// Decrypts data with private key
func VerifyWithPublicKey(msg []byte, signature []byte, pub *rsa.PublicKey) error {
	hash := crypto.Hash(crypto.SHA512)
	return rsa.VerifyPKCS1v15(pub, hash, msg, signature)
}

// Decrypts data with private key
func VerifyWithPrivateKey(msg []byte, signature []byte, priv *rsa.PrivateKey) error {
	// hash := crypto.Hash(crypto.SHA512)
	// return rsa.VerifyPKCS1v15(priv, hash, msg, signature)
	// Use private key as public key
	return nil
}

// Encrypts data with public key
func SignWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	// hash := crypto.Hash(crypto.SHA512)
	// return rsa.SignPKCS1v15(rand.Reader, priv, hash, msg)
	return nil, nil
}
