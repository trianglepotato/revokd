// Package idgen generates random identifiers.
package idgen

import (
	"crypto/rand"
	"encoding/hex"
)

// New returns a random 128-bit identifier as a hex string.
func New() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
