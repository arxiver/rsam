# rsa-modified (rsam)

Supports additional functionalites and important stuff must be done in some corner cases and some specific applications

Modified package for RSA encryption and decryption to allow large message encryption and decryption and to allow encryption through private key and decryption through public key and signature through public key and private key and vice versa. i.e. Additional functionalities to the existing crypto package

### Installation 

```shell
go get https://github.com/gossl/rsam 
```

### Usage

```go
import  (
  "bytes"
  "fmt"
  
  "github.com/gossl/rsam"
)

func main(){
  priv, pub, err := rsam.GenerateKeyPair(2048)
  if err != nil {
    panic(err)
  }
  msg := []byte("hello world")
  ciphertext, err := rsam.EncryptWithPrivateKey(msg, priv, sha256.New())
  if err != nil {
    panic(err)
  }
  plaintext, err := rsam.DecryptWithPublicKey(encrypted, pub, sha256.New())
  if err != nil {
    panic(err)
  }
  if !bytes.Equal(msg, plaintext) {
   panic(nil)
 }
}
```
