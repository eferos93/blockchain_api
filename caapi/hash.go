// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package hash provides hash implementations used for digital signature of messages sent to a Fabric network.
package caapi

import (
	"crypto/sha256"
	"crypto/sha512"
	gohash "hash"
)

// NONE returns the input message unchanged. This can be used if the signing implementation requires the full message
// bytes, not just a pre-generated digest, such as Ed25519.
func NONE(message []byte) []byte {
	return message
}

// SHA256 hash the supplied message bytes to create a digest for signing.
func SHA256(message []byte) []byte {
	return digest(sha256.New(), message)
}

// SHA384 hash the supplied message bytes to create a digest for signing.
func SHA384(message []byte) []byte {
	return digest(sha512.New384(), message)
}

func digest(hasher gohash.Hash, message []byte) []byte {
	hasher.Write(message)
	return hasher.Sum(nil)
}
