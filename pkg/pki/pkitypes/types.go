//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/sigstore/rekor/pkg/pki/identity"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
)

// RHTAS FIPS - DO NOT REMOVE
// ========================================
// ValidatePublicKey checks whether a crypto.PublicKey uses a FIPS-approved
// algorithm. Returns nil when FIPS mode is disabled or when the key is approved.
// Approved: RSA (>= 2048-bit), ECDSA, Ed25519 (FIPS 186-5).
func ValidatePublicKey(pub crypto.PublicKey) error {
	if !fips140.Enabled() {
		return nil
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("RSA key size %d below FIPS minimum 2048", k.N.BitLen())
		}
		return nil
	case *ecdsa.PublicKey:
		return nil
	case ed25519.PublicKey:
		return nil
	default:
		return fmt.Errorf("unsupported key type %T in FIPS mode", pub)
	}
}

// ========================================

// PublicKey Generic object representing a public key (regardless of format & algorithm)
type PublicKey interface {
	CanonicalValue() ([]byte, error)
	// Deprecated: EmailAddresses() will be deprecated in favor of Subjects() which will
	// also return Subject URIs present in public keys.
	EmailAddresses() []string
	Subjects() []string
	// Identities returns a list of typed keys and certificates.
	Identities() ([]identity.Identity, error)
}

// Signature Generic object representing a signature (regardless of format & algorithm)
type Signature interface {
	CanonicalValue() ([]byte, error)
	Verify(r io.Reader, k interface{}, opts ...sigsig.VerifyOption) error
}
