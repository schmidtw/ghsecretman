// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// PublicKey is a GitHub-issued libsodium public key used to encrypt secrets.
type PublicKey struct {
	KeyID string
	Key   string // base64-encoded 32-byte recipient public key
}

// sealAnonymous wraps plaintext for the given base64-encoded 32-byte recipient
// public key using libsodium's "sealed box" construction. The result is the
// base64 of (ephemeral pub || ciphertext) — the format GitHub expects.
func sealAnonymous(plaintext, recipientPubKeyB64 string) (string, error) {
	pkBytes, err := base64.StdEncoding.DecodeString(recipientPubKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode public key: %w", err)
	}
	if len(pkBytes) != 32 {
		return "", fmt.Errorf("public key must be 32 bytes, got %d", len(pkBytes))
	}
	var pk [32]byte
	copy(pk[:], pkBytes)
	sealed, err := box.SealAnonymous(nil, []byte(plaintext), &pk, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("seal anonymous: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}
