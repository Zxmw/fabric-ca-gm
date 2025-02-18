/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tcert

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/chenjz24/crypto/rsa"
	"github.com/chenjz24/crypto/x509"

	"github.com/chenjz24/crypto/aes"

	"github.com/chenjz24/crypto/ecdsa"

	"github.com/cloudflare/cfssl/log"
)

const (
	// AESKeyLength is the default AES key length
	AESKeyLength = 32
)

var (
	//RootPreKeySize is the default value of root key
	RootPreKeySize = 48
)

// GenerateIntUUID returns a UUID based on RFC 4122 returning a big.Int
func GenerateIntUUID() (*big.Int, error) {
	uuid, err := GenerateBytesUUID()
	if err != nil {
		return nil, err
	}
	z := big.NewInt(0)
	return z.SetBytes(uuid), nil
}

// GenerateBytesUUID returns a UUID based on RFC 4122 returning the generated bytes
func GenerateBytesUUID() ([]byte, error) {
	uuid := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, uuid)
	if err != nil {
		return nil, err
	}

	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80

	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40

	return uuid, nil
}

// CBCPKCS7Encrypt combines CBC encryption and PKCS7 padding
func CBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	return CBCEncrypt(key, PKCS7Padding(src))
}

// CBCEncrypt encrypts using CBC mode
func CBCEncrypt(key, s []byte) ([]byte, error) {
	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(s)%aes.BlockSize != 0 {
		return nil, errors.New("CBCEncrypt failure: plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(s))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("CBCEncrypt failure in io.ReadFull: %s", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], s)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	return ciphertext, nil
}

// PKCS7Padding pads as prescribed by the PKCS7 standard
func PKCS7Padding(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

//ConvertDERToPEM returns data from DER to PEM format
//DERData is DER
func ConvertDERToPEM(der []byte, datatype string) []byte {
	pemByte := pem.EncodeToMemory(
		&pem.Block{
			Type:  datatype,
			Bytes: der,
		},
	)
	return pemByte
}

//GenNumber generates random numbers of type *big.Int with fixed length
func GenNumber(numlen *big.Int) (*big.Int, error) {
	lowerBound := new(big.Int).Exp(big.NewInt(10), new(big.Int).Sub(numlen, big.NewInt(1)), nil)
	upperBound := new(big.Int).Exp(big.NewInt(10), numlen, nil)
	randomNum, err := rand.Int(rand.Reader, upperBound)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate random number: %s", err)
	}
	val := new(big.Int).Add(randomNum, lowerBound)
	valMod := new(big.Int).Mod(val, upperBound)

	if valMod.Cmp(lowerBound) == -1 {
		newval := new(big.Int).Add(valMod, lowerBound)
		return newval, nil
	}
	return valMod, nil
}

// GetEnrollmentIDFromCert retrieves Enrollment Id from certificate
func GetEnrollmentIDFromCert(ecert *x509.Certificate) string {
	return ecert.Subject.CommonName
}

//GetCertificate returns interface containing *rsa.PublicKey or ecdsa.PublicKey
func GetCertificate(certificate []byte) (*x509.Certificate, error) {

	var certificates []*x509.Certificate
	var isvalidCert bool
	var err error

	block, _ := pem.Decode(certificate)
	if block == nil {
		certificates, err = x509.ParseCertificates(certificate)
		if err != nil {
			log.Error("Certificate Parse failed")
			return nil, errors.New("DER Certificate Parse failed")
		} //else {
		isvalidCert = ValidateCert(certificates[0])
		if !isvalidCert {
			log.Error("Certificate expired")
			return nil, errors.New("Certificate expired")
		}
		//}
	} else {
		certificates, err = x509.ParseCertificates(block.Bytes)
		if err != nil {
			log.Error("PEM Certificatre Parse failed")
			return nil, errors.New("PEM  Certificate Parse failed")
		} //else {
		isvalidCert = ValidateCert(certificates[0])
		if !isvalidCert {
			log.Error("Certificate expired")
			return nil, errors.New("Certificate expired")
		}
		//}
	}
	return certificates[0], nil

}

//GetCertitificateSerialNumber returns serial number for Certificate byte
//return -1 , if there is problem with the cert
func GetCertitificateSerialNumber(certificatebyte []byte) (*big.Int, error) {
	certificate, error := GetCertificate(certificatebyte)
	if error != nil {
		log.Error("Not a valid Certificate")
		return big.NewInt(-1), error
	}
	return certificate.SerialNumber, nil
}

//ValidateCert checks for expiry in the certificate cert
//Does not check for revocation
func ValidateCert(cert *x509.Certificate) bool {
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter
	currentTime := time.Now()
	diffFromExpiry := notAfter.Sub(currentTime)
	diffFromStart := currentTime.Sub(notBefore)
	return ((diffFromExpiry > 0) && (diffFromStart > 0))
}

// CBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding
func CBCPKCS7Decrypt(key, src []byte) ([]byte, error) {
	pt, err := CBCDecrypt(key, src)
	if err != nil {

		return nil, err
	}

	original, err := PKCS7UnPadding(pt)
	if err != nil {

		return nil, err
	}

	return original, nil
}

// CBCDecrypt decrypts using CBC mode
func CBCDecrypt(key, src []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {

		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(src) < aes.BlockSize {

		return nil, errors.New("ciphertext too short")
	}
	iv := src[:aes.BlockSize]
	src = src[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(src)%aes.BlockSize != 0 {

		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(src, src)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	return src, nil
}

// PKCS7UnPadding unpads as prescribed by the PKCS7 standard
func PKCS7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > aes.BlockSize || unpadding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return src[:(length - unpadding)], nil
}

//CreateRootPreKey method generates root key
func CreateRootPreKey() string {
	var cooked string
	key := make([]byte, RootPreKeySize)
	rand.Reader.Read(key)
	cooked = base64.StdEncoding.EncodeToString(key)
	return cooked
}

// GetPrivateKey returns ecdsa.PrivateKey or rsa.privateKey object for the private Key Bytes
func GetPrivateKey(buf []byte) (interface{}, error) {
	var err error
	var privateKey interface{}

	block, _ := pem.Decode(buf)
	if block == nil {
		privateKey, err = ParsePrivateKey(buf)
		if err != nil {
			return nil, fmt.Errorf("Failure parsing DER-encoded private key: %s", err)
		}
	} else {
		privateKey, err = ParsePrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Failure parsing PEM private key: %s", err)
		}
	}

	switch privateKey := privateKey.(type) {
	case *rsa.PrivateKey:
		return privateKey, nil
	case *ecdsa.PrivateKey:
		return privateKey, nil
	default:
		return nil, errors.New("Key is neither RSA nor ECDSA")
	}

}

// ParsePrivateKey parses private key
func ParsePrivateKey(der []byte) (interface{}, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("Key is neither RSA nor ECDSA")
		}
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failure parsing private key: %s", err)
	}
	return key, nil
}

// LoadCert loads a certificate from a file
func LoadCert(path string) (*x509.Certificate, error) {
	certBuf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return GetCertificate(certBuf)
}

// LoadKey loads a private key from a file
func LoadKey(path string) (interface{}, error) {
	keyBuf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := GetPrivateKey(keyBuf)
	if err != nil {
		return nil, err
	}
	return key, nil
}
