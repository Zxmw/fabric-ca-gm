/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package x509

import (
	"fmt"

	"github.com/chenjz24/crypto/x509"

	"github.com/hyperledger/fabric-ca/lib/attrmgr"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
)

// NewSigner is constructor for Signer
func NewSigner(key bccsp.Key, cert []byte) (*Signer, error) {
	s := &Signer{
		key:       key,
		certBytes: cert,
	}
	var err error
	s.cert, err = util.GetX509CertificateFromPEM(s.certBytes)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to unmarshal X509 certificate bytes")
	}
	s.name = util.GetEnrollmentIDFromX509Certificate(s.cert)
	return s, nil
}

// Signer represents a signer
// Each identity may have multiple signers, currently one ecert and multiple tcerts
type Signer struct {
	// Private key
	key bccsp.Key
	// Certificate bytes
	certBytes []byte
	// X509 certificate that is constructed from the cert bytes associated with this signer
	cert *x509.Certificate
	// Common name from the certificate associated with this signer
	name string
}

// Key returns the key bytes of this signer
func (s *Signer) Key() bccsp.Key {
	return s.key
}

// Cert returns the cert bytes of this signer
func (s *Signer) Cert() []byte {
	return s.certBytes
}

// GetX509Cert returns the X509 certificate for this signer
func (s *Signer) GetX509Cert() *x509.Certificate {
	return s.cert
}

// GetName returns common name that is retrieved from the Subject of the certificate
// associated with this signer
func (s *Signer) GetName() string {
	return s.name
}

// Attributes returns the attributes that are in the certificate
func (s *Signer) Attributes() (*attrmgr.Attributes, error) {
	cert := s.GetX509Cert()
	attrs, err := attrmgr.New().GetAttributesFromCert(cert)
	if err != nil {
		return nil, fmt.Errorf("Failed getting attributes for '%s': %s", s.name, err)
	}
	return attrs, nil
}
