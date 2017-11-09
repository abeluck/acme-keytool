package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

func determineKeyIDFromCert(c *x509.Certificate) string {
	h := sha256.New()
	h.Write(c.RawSubjectPublicKeyInfo)
	return strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(h.Sum(nil)), "="))
}

func getPublicKey(pk crypto.PrivateKey) crypto.PublicKey {
	switch pkv := pk.(type) {
	case *rsa.PrivateKey:
		return &pkv.PublicKey
	case *ecdsa.PrivateKey:
		return &pkv.PublicKey
	default:
		panic("unsupported key type")
	}
}

func determineKeyIDFromKey(pk crypto.PrivateKey) (string, error) {
	return determineKeyIDFromKeyIntl(getPublicKey(pk), pk)
}

func determineKeyIDFromKeyIntl(pubk crypto.PublicKey, pk crypto.PrivateKey) (string, error) {
	cc := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	cb, err := x509.CreateCertificate(rand.Reader, cc, cc, pubk, pk)
	if err != nil {
		return "", err
	}

	c, err := x509.ParseCertificate(cb)
	if err != nil {
		return "", err
	}

	return determineKeyIDFromCert(c), nil
}

func determineCertificateID(url string) string {
	h := sha256.New()
	h.Write([]byte(url))
	b := h.Sum(nil)
	return strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(b), "="))
}

// Parse a DER private key. The key can be RSA or ECDSA. PKCS8 containers are
// supported.
func LoadPrivateKeyDER(der []byte) (crypto.PrivateKey, error) {
	pk, err := x509.ParsePKCS1PrivateKey(der)
	if err == nil {
		return pk, nil
	}

	pk2, err := x509.ParsePKCS8PrivateKey(der)
	if err == nil {
		switch pk2 := pk2.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return pk2, nil
		default:
			return nil, fmt.Errorf("unknown private key type")
		}
	}

	epk, err := x509.ParseECPrivateKey(der)
	if err == nil {
		return epk, nil
	}

	return nil, fmt.Errorf("failed to parse private key")
}

// Load a PEM private key from a stream.
func LoadPrivateKey(keyPEMBlock []byte) (crypto.PrivateKey, error) {
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			return nil, fmt.Errorf("failed to parse key PEM data")
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
	}

	pk, err := LoadPrivateKeyDER(keyDERBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

// ----------------

func main() {

	if len(os.Args) != 2 {
		fmt.Println("usage: ", os.Args[0], " <key_file>")
		return
	}
	data, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("can't read file:", os.Args[1])
		panic(err)
	}
	pk, err := LoadPrivateKey([]byte(string(data)))
	if err != nil {
		fmt.Println("failed to load private key: ", err)
		panic(err)
	}
	actualKeyID, err := determineKeyIDFromKey(pk)

	fmt.Println(actualKeyID)

}
