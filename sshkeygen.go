package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// type dig
type TDSshKeySize int

const (
	// AlgorithmSHA1 should be used for compatibility with Google Authenticator.
	//
	// See https://github.com/pquerna/otp/issues/55 for additional details.
	TDSKSize2048 TDSshKeySize = iota
	TDSKSize4096
)

type CDigSshKeyGenerator struct {
	keysize TDSshKeySize
}

func newDigSshKeyGenetorDefault() *CDigSshKeyGenerator {
	return newDigSshKeyGenetor(TDSKSize4096)
}
func newDigSshKeyGenetor(keysize TDSshKeySize) *CDigSshKeyGenerator {
	return &CDigSshKeyGenerator{
		keysize: keysize,
	}
}

/*
* generate ssh key pair.
return: 1: private key, 2: public key, 3: error
*/
func (instSelf *CDigSshKeyGenerator) Generate() (string, string, error) {
	keySize := 2048
	if instSelf.keysize == TDSKSize4096 {
		keySize = 4096
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return "", "", err
	}

	publicKeyPEM, err := instSelf.generatePublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	var bufPrivate bytes.Buffer
	writerPrivate := bufio.NewWriter(&bufPrivate)
	err = pem.Encode(writerPrivate, privateKeyPEM)
	if err != nil {
		return "", "", err
	}
	writerPrivate.Flush()
	var bufPublic bytes.Buffer
	writerPublic := bufio.NewWriter(&bufPublic)
	err = pem.Encode(writerPublic, publicKeyPEM)
	if err != nil {
		return "", "", err
	}
	writerPublic.Flush()

	//publicKeyPEM.Bytes

	return bufPrivate.String(), string(publicKeyPEM.Bytes), nil //bufPublic.String(), nil
}
func (instSelf *CDigSshKeyGenerator) generatePublicKey(publicKey *rsa.PublicKey) (*pem.Block, error) {
	pub, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	pubBytes := ssh.MarshalAuthorizedKey(pub)
	return &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubBytes,
	}, nil
}

func regentPublickeyFromPrivateKey(privatekey string) {
	privatePem, restbyte := pem.Decode([]byte(privatekey))
	if restbyte != nil {
		fmt.Println("regen pulbic key error, restbyte is: ", restbyte)
	}

	privateKey1, err := x509.ParsePKCS1PrivateKey(privatePem.Bytes)
	if err != nil {
		fmt.Println("regen pulbic key error: ", err)
		return
	}

	pub, err := ssh.NewPublicKey(&privateKey1.PublicKey)
	if err != nil {
		fmt.Println("regen pulbic key error: ", err)
		return
	}
	pubBytes := ssh.MarshalAuthorizedKey(pub)

	fmt.Println(string(pubBytes))

}
