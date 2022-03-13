package rsam

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"hash"
	"os"

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
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey, hash hash.Hash) ([]byte, error) {
	var err error
	var ciphertext, c []byte
	chunkSize := pub.Size() - 2*hash.Size() - 2
	if chunkSize < 1 {
		return nil, errors.New("Invalid public key: public key is too short, pub.Size() - 2*hash.Size() - 2 must be greater than 0")
	}
	// TODO: GO ROUTINE HERE
	for i := 0; i < len(msg); i += chunkSize {
		if i+chunkSize > len(msg) {
			c, err = rsa.EncryptOAEP(hash, rand.Reader, pub, msg[i:], nil)
		} else {
			c, err = rsa.EncryptOAEP(hash, rand.Reader, pub, msg[i:i+chunkSize], nil)
		}
		if err != nil {
			return nil, err
		}
		ciphertext = append(ciphertext, c...)
	}
	return ciphertext, err
}

// Decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey, hash hash.Hash) ([]byte, error) {
	var plaintext, p []byte
	var err error
	chunkSize := priv.Size()
	// TODO: GO ROUTINE HERE
	for i := 0; i < len(ciphertext); i += chunkSize {
		if i+chunkSize > len(ciphertext) {
			p, err = rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext[i:], nil)
		} else {
			p, err = rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext[i:i+chunkSize], nil)
		}
		if err != nil {
			return nil, err
		}
		plaintext = append(plaintext, p...)
	}
	return plaintext, nil
}

// Encrypts data with public key
func EncryptWithPrivateKey(msg []byte, priv *rsa.PrivateKey, hash hash.Hash) ([]byte, error) {
	var err error
	var ciphertext, c []byte
	chunkSize := priv.Size() - 2*hash.Size() - 2
	if chunkSize < 1 {
		return nil, errors.New("Invalid private key: private key is too short, pub.Size() - 2*hash.Size() - 2 must be greater than 0")
	}
	for i := 0; i < len(msg); i += chunkSize {
		if i+chunkSize > len(msg) {
			c, err = cry.EncryptOAEPM(hash, rand.Reader, priv, msg[i:], nil)
		} else {
			c, err = cry.EncryptOAEPM(hash, rand.Reader, priv, msg[i:i+chunkSize], nil)
		}
		if err != nil {
			return nil, err
		}
		ciphertext = append(ciphertext, c...)
	}
	return ciphertext, err
}

// Decrypts data with private key
func DecryptWithPublicKey(ciphertext []byte, pub *rsa.PublicKey, hash hash.Hash) ([]byte, error) {
	var plaintext []byte
	chunkSize := pub.Size()
	var c []byte
	for i := 0; i < len(ciphertext); i += chunkSize {
		if i+chunkSize > len(ciphertext) {
			c = ciphertext[i:]
		} else {
			c = ciphertext[i : i+chunkSize]
		}
		m, err := cry.DecryptOAEPM(hash, rand.Reader, pub, c[:], nil)
		if err != nil {
			return nil, err
		}
		plaintext = append(plaintext, m...)
	}
	return plaintext, nil
}

// Decrypts data with private key
func SignWithPrivateKey(msg []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := crypto.Hash(crypto.SHA512)
	hashed := sha256.Sum256(msg)
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, hash, hashed[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// Decrypts data with private key
func VerifyWithPublicKey(msg []byte, signature []byte, pub *rsa.PublicKey) error {
	hash := crypto.Hash(crypto.SHA512)
	hashed := sha256.Sum256(msg)
	return rsa.VerifyPKCS1v15(pub, hash, hashed[:], signature)
}

// Decrypts data with private key
func VerifyWithPrivateKey(msg []byte, signature []byte, priv *rsa.PrivateKey) error {
	hash := crypto.Hash(crypto.SHA256)
	hashed := sha256.Sum256(msg)
	return cry.VerifyByPrivate(priv, hash, hashed[:], signature)
}

// Encrypts data with public key
func SignWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := crypto.Hash(crypto.SHA256)
	hashed := sha256.Sum256(msg)
	return cry.SignByPublic(rand.Reader, pub, hash, hashed[:])
}

// Returns base64 encoded key from file
func B64EncodeKeyFile(path string) (string, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return B64EncodeKeyString(string(bytes)), nil
}

// Returns decoding of base64 encoded key from file
func B64DecodeKeyFile(path string) (string, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return B64DecodeKeyString(string(bytes))
}

// Returns base64 encoded public key from string
func B64EncodeKeyString(key string) string {
	return base64.StdEncoding.EncodeToString([]byte(key))
}

// Returns base64 encoded public key from string
func B64DecodeKeyString(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	return string(decoded), err
}
