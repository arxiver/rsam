# rsa-modified (rsam)

Supports additional functionalites and important stuff must be done in some corner cases and some specific applications

Modified package for RSA encryption and decryption to allow **large** message encryption and decryption and to **allow encryption through private key and decryption through public key** and signature through public key and private key and vice versa. i.e. Additional functionalities to the existing crypto package


### Installation 

```shell
go get "github.com/gossl/rsam"
```

### Usage

```go
package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/gossl/rsam"
)

func main() {
	priv, pub, err := rsam.GeneratePairKeys(2048)
	if err != nil {
		panic(err)
	}
	msg := []byte("hello world")
	ciphertext, err := rsam.EncryptWithPrivateKey(msg, priv, sha256.New())
	if err != nil {
		panic(err)
	}
	plaintext, err := rsam.DecryptWithPublicKey(ciphertext, pub, sha256.New())
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(msg, plaintext) {
		panic(nil)
	}
	fmt.Println(string(plaintext))
}
```
