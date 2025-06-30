package caapi

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
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
