package cry

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/gossl/rsam/randutil"
)

var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

func SignPKCS1v15(rand io.Reader, priv *rsa.PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
	hashLen, prefix, err := pkcs1v15HashInfo(hash, len(hashed))
	if err != nil {
		return nil, err
	}

	tLen := len(prefix) + hashLen
	k := priv.Size()
	if k < tLen+11 {
		return nil, rsa.ErrMessageTooLong
	}

	// EM = 0x00 || 0x01 || PS || 0x00 || T
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k-hashLen], prefix)
	copy(em[k-hashLen:k], hashed)

	m := new(big.Int).SetBytes(em)
	c, err := decryptAndCheck(rand, priv, m)
	if err != nil {
		return nil, err
	}

	return c.FillBytes(em), nil
}

func SignByPublic(rand io.Reader, pub *rsa.PublicKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
	hashLen, prefix, err := pkcs1v15HashInfo(hash, len(hashed))
	if err != nil {
		return nil, err
	}

	tLen := len(prefix) + hashLen
	k := pub.Size()
	if k < tLen+11 {
		return nil, rsa.ErrMessageTooLong
	}

	// EM = 0x00 || 0x01 || PS || 0x00 || T
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k-hashLen], prefix)
	copy(em[k-hashLen:k], hashed)

	m := new(big.Int).SetBytes(em)
	c, err := decryptAndCheckByPublic(rand, pub, m)
	if err != nil {
		return nil, err
	}

	return c.FillBytes(em), nil
}

func SignPSSByPublic(rand io.Reader, pub *rsa.PublicKey, hash crypto.Hash, digest []byte, opts *PSSOptions) ([]byte, error) {
	if opts != nil && opts.Hash != 0 {
		hash = opts.Hash
	}

	saltLength := opts.saltLength()
	switch saltLength {
	case PSSSaltLengthAuto:
		saltLength = pub.Size() - 2 - hash.Size()
	case PSSSaltLengthEqualsHash:
		saltLength = hash.Size()
	}

	salt := make([]byte, saltLength)
	if rand != nil {
		if _, err := io.ReadFull(rand, salt); err != nil {
			return nil, err
		}
	}
	return signPSSWithSaltByPublic(rand, pub, hash, digest, salt)
}

// signPSSWithSaltByPublic calculates the signature of hashed using PSS with specified salt.
// Note that hashed must be the result of hashing the input message using the
// given hash function. salt is a random sequence of bytes whose length will be
// later used to verify the signature.
func signPSSWithSaltByPublic(rand io.Reader, pub *rsa.PublicKey, hash crypto.Hash, hashed, salt []byte) ([]byte, error) {
	emBits := pub.N.BitLen() - 1
	em, err := emsaPSSEncode(hashed, emBits, salt, hash.New())
	if err != nil {
		return nil, err
	}
	m := new(big.Int).SetBytes(em)
	c, err := decryptAndCheckByPublic(rand, pub, m)
	if err != nil {
		return nil, err
	}
	s := make([]byte, pub.Size())
	return c.FillBytes(s), nil
}

// signPSSWithSaltByPublic calculates the signature of hashed using PSS with specified salt.
// Note that hashed must be the result of hashing the input message using the
// given hash function. salt is a random sequence of bytes whose length will be
// later used to verify the signature.
func signPSSWithSalt(rand io.Reader, priv *rsa.PrivateKey, hash crypto.Hash, hashed, salt []byte) ([]byte, error) {
	emBits := priv.N.BitLen() - 1
	em, err := emsaPSSEncode(hashed, emBits, salt, hash.New())
	if err != nil {
		return nil, err
	}
	m := new(big.Int).SetBytes(em)
	c, err := decryptAndCheck(rand, priv, m)
	if err != nil {
		return nil, err
	}
	s := make([]byte, priv.Size())
	return c.FillBytes(s), nil
}

func emsaPSSEncode(mHash []byte, emBits int, salt []byte, hash hash.Hash) ([]byte, error) {
	// See RFC 8017, Section 9.1.1.

	hLen := hash.Size()
	sLen := len(salt)
	emLen := (emBits + 7) / 8

	// 1.  If the length of M is greater than the input limitation for the
	//     hash function (2^61 - 1 octets for SHA-1), output "message too
	//     long" and stop.
	//
	// 2.  Let mHash = Hash(M), an octet string of length hLen.

	if len(mHash) != hLen {
		return nil, errors.New("crypto/rsa: input must be hashed with given hash")
	}

	// 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.

	if emLen < hLen+sLen+2 {
		return nil, errors.New("crypto/rsa: key size too small for PSS signature")
	}

	em := make([]byte, emLen)
	psLen := emLen - sLen - hLen - 2
	db := em[:psLen+1+sLen]
	h := em[psLen+1+sLen : emLen-1]

	// 4.  Generate a random octet string salt of length sLen; if sLen = 0,
	//     then salt is the empty string.
	//
	// 5.  Let
	//       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
	//
	//     M' is an octet string of length 8 + hLen + sLen with eight
	//     initial zero octets.
	//
	// 6.  Let H = Hash(M'), an octet string of length hLen.

	var prefix [8]byte

	hash.Write(prefix[:])
	hash.Write(mHash)
	hash.Write(salt)

	h = hash.Sum(h[:0])
	hash.Reset()

	// 7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
	//     zero octets. The length of PS may be 0.
	//
	// 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
	//     emLen - hLen - 1.

	db[psLen] = 0x01
	copy(db[psLen+1:], salt)

	// 9.  Let dbMask = MGF(H, emLen - hLen - 1).
	//
	// 10. Let maskedDB = DB \xor dbMask.

	mgf1XOR(db, hash, h)

	// 11. Set the leftmost 8 * emLen - emBits bits of the leftmost octet in
	//     maskedDB to zero.

	db[0] &= 0xff >> (8*emLen - emBits)

	// 12. Let EM = maskedDB || H || 0xbc.
	em[emLen-1] = 0xbc

	// 13. Output EM.
	return em, nil
}

func pkcs1v15HashInfo(hash crypto.Hash, inLen int) (hashLen int, prefix []byte, err error) {
	// Special case: crypto.Hash(0) is used to indicate that the data is
	// signed directly.
	if hash == 0 {
		return inLen, nil, nil
	}

	hashLen = hash.Size()
	if inLen != hashLen {
		return 0, nil, errors.New("crypto/rsa: input must be hashed message")
	}
	prefix, ok := hashPrefixes[hash]
	if !ok {
		return 0, nil, errors.New("crypto/rsa: unsupported hash function")
	}
	return
}

func decryptAndCheck(random io.Reader, priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	m, err = decrypt(random, priv, c)
	if err != nil {
		return nil, err
	}

	// In order to defend against errors in the CRT computation, m^e is
	// calculated, which should match the original ciphertext.
	check := encrypt(new(big.Int), &priv.PublicKey, m)
	if c.Cmp(check) != 0 {
		return nil, errors.New("rsa: internal error")
	}
	return m, nil
}

func decryptAndCheckByPublic(random io.Reader, pub *rsa.PublicKey, c *big.Int) (m *big.Int, err error) {
	m, err = decryptByPublic(random, pub, c)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func encrypt(c *big.Int, pub *rsa.PublicKey, m *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	fmt.Println(c.Int64())
	return c
}

func encryptByPrivateKey(c *big.Int, priv *rsa.PrivateKey, m *big.Int) *big.Int {
	c.Exp(m, priv.D, priv.N)
	return c
}

func EncryptOAEPM(hash hash.Hash, random io.Reader, priv *rsa.PrivateKey, msg []byte, label []byte) ([]byte, error) {
	hash.Reset()
	k := priv.Size()
	if len(msg) > k-2*hash.Size()-2 {
		return nil, ErrMessageTooLong
	}

	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	em := make([]byte, k)
	seed := em[1 : 1+hash.Size()]
	db := em[1+hash.Size():]

	copy(db[0:hash.Size()], lHash)
	db[len(db)-len(msg)-1] = 1
	copy(db[len(db)-len(msg):], msg)
	if random != nil {
		_, err := io.ReadFull(random, seed)
		if err != nil {
			return nil, err
		}
	}

	mgf1XOR(db, hash, seed)
	mgf1XOR(seed, hash, db)

	m := new(big.Int)
	m.SetBytes(em)
	c := encryptByPrivateKey(new(big.Int), priv, m)

	out := make([]byte, k)
	return c.FillBytes(out), nil
}

// decrypt performs an RSA decryption, resulting in a plaintext integer. If a
// random source is given, RSA blinding is used.
func decrypt(random io.Reader, priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	// (agl): can we get away with reusing blinds?
	if c.Cmp(priv.N) > 0 {
		err = rsa.ErrDecryption
		return
	}
	if priv.N.Sign() == 0 {
		return nil, rsa.ErrDecryption
	}

	var ir *big.Int
	if random != nil {
		randutil.MaybeReadByte(random)

		// Blinding enabled. Blinding involves multiplying c by r^e.
		// Then the decryption operation performs (m^e * r^e)^d mod n
		// which equals mr mod n. The factor of r can then be removed
		// by multiplying by the multiplicative inverse of r.

		var r *big.Int
		ir = new(big.Int)
		for {
			r, err = rand.Int(random, priv.N)
			if err != nil {
				return
			}
			if r.Cmp(bigZero) == 0 {
				r = bigOne
			}
			ok := ir.ModInverse(r, priv.N)
			if ok != nil {
				break
			}
		}
		bigE := big.NewInt(int64(priv.E))
		rpowe := new(big.Int).Exp(r, bigE, priv.N) // N != 0
		cCopy := new(big.Int).Set(c)
		cCopy.Mul(cCopy, rpowe)
		cCopy.Mod(cCopy, priv.N)
		c = cCopy
	}

	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		// We have the precalculated values needed for the CRT.
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}

	if ir != nil {
		// Unblind.
		m.Mul(m, ir)
		m.Mod(m, priv.N)
	}

	return
}

func DecryptOAEPM(hash hash.Hash, random io.Reader, pub *rsa.PublicKey, ciphertext []byte, label []byte) ([]byte, error) {
	k := pub.Size()
	if len(ciphertext) > k ||
		k < hash.Size()*2+2 {
		return nil, rsa.ErrDecryption
	}

	c := new(big.Int).SetBytes(ciphertext)

	m, err := decryptByPublic(random, pub, c)
	if err != nil {
		return nil, err
	}

	hash.Write(label)
	// lHash := hash.Sum(nil)
	hash.Reset()

	// We probably leak the number of leading zeros.
	// It's not clear that we can do anything about this.
	em := m.FillBytes(make([]byte, k))

	// firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)

	seed := em[1 : hash.Size()+1]
	db := em[hash.Size()+1:]

	mgf1XOR(seed, hash, db)
	mgf1XOR(db, hash, seed)

	// lHash2 := db[0:hash.Size()]

	// We have to validate the plaintext in constant time in order to avoid
	// attacks like: J. Manger. A Chosen Ciphertext Attack on RSA Optimal
	// Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1
	// v2.0. In J. Kilian, editor, Advances in Cryptology.
	// lHash2Good := subtle.ConstantTimeCompare(lHash, lHash2)

	// The remainder of the plaintext must be zero or more 0x00, followed
	// by 0x01, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the 0x01
	//   index: the offset of the first 0x01 byte
	//   invalid: 1 iff we saw a non-zero byte before the 0x01.
	var lookingForIndex, index, invalid int
	lookingForIndex = 1
	rest := db[hash.Size():]

	for i := 0; i < len(rest); i++ {
		equals0 := subtle.ConstantTimeByteEq(rest[i], 0)
		equals1 := subtle.ConstantTimeByteEq(rest[i], 1)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals1, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals1, 0, lookingForIndex)
		invalid = subtle.ConstantTimeSelect(lookingForIndex&^equals0, 1, invalid)
	}

	// if firstByteIsZero&lHash2Good&^invalid&^lookingForIndex != 1 {
	// 	return nil, rsa.ErrDecryption
	// }

	return rest[index+1:], nil
}

// decrypt performs an RSA decryption, resulting in a plaintext integer. If a
// random source is given, RSA blinding is used.
func decryptByPublic(random io.Reader, pub *rsa.PublicKey, c *big.Int) (m *big.Int, err error) {
	// (agl): can we get away with reusing blinds?
	if c.Cmp(pub.N) > 0 {
		err = rsa.ErrDecryption
		return
	}
	if pub.N.Sign() == 0 {
		return nil, rsa.ErrDecryption
	}
	bigE := big.NewInt(int64(pub.E))
	var ir *big.Int
	if random != nil {
		randutil.MaybeReadByte(random)

		// Blinding enabled. Blinding involves multiplying c by r^e.
		// Then the decryption operation performs (m^e * r^e)^d mod n
		// which equals mr mod n. The factor of r can then be removed
		// by multiplying by the multiplicative inverse of r.

		var r *big.Int
		ir = new(big.Int)
		for {
			r, err = rand.Int(random, pub.N)
			if err != nil {
				return
			}
			if r.Cmp(bigZero) == 0 {
				r = bigOne
			}
			ok := ir.ModInverse(r, pub.N)
			if ok != nil {
				break
			}
		}
		rpowe := new(big.Int).Exp(r, bigE, pub.N) // N != 0
		cCopy := new(big.Int).Set(c)
		cCopy.Mul(cCopy, rpowe)
		cCopy.Mod(cCopy, pub.N)
		c = cCopy
	}
	m, err = new(big.Int).Exp(c, bigE, pub.N), nil
	return
}

func VerifyByPrivate(priv *rsa.PrivateKey, hash crypto.Hash, hashed []byte, sig []byte) error {
	hashLen, prefix, err := pkcs1v15HashInfo(hash, len(hashed))
	if err != nil {
		return err
	}

	tLen := len(prefix) + hashLen
	k := priv.Size()
	if k < tLen+11 {
		return rsa.ErrVerification
	}

	// RFC 8017 Section 8.2.2: If the length of the signature S is not k
	// octets (where k is the length in octets of the RSA modulus n), output
	// "invalid signature" and stop.
	if k != len(sig) {
		return rsa.ErrVerification
	}

	c := new(big.Int).SetBytes(sig)
	m := encryptByPrivateKey(new(big.Int), priv, c)
	em := m.FillBytes(make([]byte, k))
	// EM = 0x00 || 0x01 || PS || 0x00 || T

	ok := subtle.ConstantTimeByteEq(em[0], 0)
	ok &= subtle.ConstantTimeByteEq(em[1], 1)
	ok &= subtle.ConstantTimeCompare(em[k-hashLen:k], hashed)
	ok &= subtle.ConstantTimeCompare(em[k-tLen:k-hashLen], prefix)
	ok &= subtle.ConstantTimeByteEq(em[k-tLen-1], 0)

	for i := 2; i < k-tLen-1; i++ {
		ok &= subtle.ConstantTimeByteEq(em[i], 0xff)
	}

	if ok != 1 {
		return rsa.ErrVerification
	}

	return nil
}

func BytesToBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func BigIntToBytes(n *big.Int) []byte {
	return n.Bytes()
}

// mgf1XOR XORs the bytes in out with a mask generated using the MGF1 function
// specified in PKCS #1 v2.1.
func mgf1XOR(out []byte, hash hash.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(out) {
		hash.Write(seed)
		hash.Write(counter[0:4])
		digest = hash.Sum(digest[:0])
		hash.Reset()

		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		incCounter(&counter)
	}
}

// incCounter increments a four byte, big-endian counter.
func incCounter(c *[4]byte) {
	if c[3]++; c[3] != 0 {
		return
	}
	if c[2]++; c[2] != 0 {
		return
	}
	if c[1]++; c[1] != 0 {
		return
	}
	c[0]++
}

var ErrMessageTooLong = errors.New("message too long")
