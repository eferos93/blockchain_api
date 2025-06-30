package caapi

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
)

func ecdsaPrivateKeySign(privateKey *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	n := privateKey.Params().Params().N

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
	if err != nil {
		return nil, err
	}

	s = canonicalECDSASignatureSValue(s, n)

	signature, err := asn1ECDSASignature(r, s)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func canonicalECDSASignatureSValue(s *big.Int, curveN *big.Int) *big.Int {
	halfOrder := new(big.Int).Rsh(curveN, 1)
	if s.Cmp(halfOrder) <= 0 {
		return s
	}

	// Set s to N - s so it is in the lower part of signature space, less or equal to half order
	return new(big.Int).Sub(curveN, s)
}

type ecdsaSignature struct {
	R, S *big.Int
}

func asn1ECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ecdsaSignature{
		R: r,
		S: s,
	})
}

func ecdsaPrivateKeyVerify(publicKey *ecdsa.PublicKey, digest []byte, signature []byte) (bool, error) {
	// Parse the ASN.1 encoded signature
	r, s, err := parseASN1ECDSASignature(signature)
	if err != nil {
		return false, err
	}

	// Verify the signature
	valid := ecdsa.Verify(publicKey, digest, r, s)
	return valid, nil
}

func parseASN1ECDSASignature(signature []byte) (*big.Int, *big.Int, error) {
	var sig ecdsaSignature
	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return nil, nil, err
	}

	return sig.R, sig.S, nil
}

func pemToECDSAPrivateKey(privateKeyPEM []byte) (*ecdsa.PrivateKey, error) {
	// Decode the PEM block
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse the private key based on the block type
	var privateKey any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8 format
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %v", err)
		}
	case "EC PRIVATE KEY":
		// EC format
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	// Ensure it's an ECDSA private key
	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an ECDSA key, got type: %T", privateKey)
	}

	return ecdsaKey, nil
}
