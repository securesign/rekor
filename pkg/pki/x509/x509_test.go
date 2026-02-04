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

package x509

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/sigstore/rekor/pkg/pki/identity"
	"github.com/sigstore/rekor/pkg/pki/x509/testutils"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Generated with:
// openssl genrsa -out myprivate.pem 2048
// openssl pkcs8 -topk8 -in myprivate.pem  -nocrypt'
const pkcs1v15Priv = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQD9ZcVkpq49ZHYw
BgognGlSbAn+p3/OCQp94QrJyZNYKvWcGRhAwMLQZgXwv10l+rE+b1A/bLPXo0Bd
wMGjqj/coHB694yaLHGyRVDQEFBtsULBz/JF/wKCoc+U8e+6z/rPzBUSXYI35EOe
JFhBIEM7tC7zEFnjMinaqKPCgrdIuRd9uTo7Msw7MXbvt8FG92ZjdRduQW30920N
WMuRS4AJDp5UKiW10iiZmX9OB+H9O+r4ADgL+QzSPgNYwX8/4VcCr6hZ4/gZufrp
PazIDdXlb/OJCFHYX7K1gDA64Zrg4VeqyIBkBgSqAxImc50+KWtKUyrkGtA95nx1
WK2bxLdpAgMBAAECggEASQ+e6nZkpq7gpNgY824lr+4Ws6X346AXtlO8mJHWOgWo
62kQ5RqvEQdZjyCd6uVtVWMi8CaXdAVN+boqGtZrs2FPDSVzFMDbx1rVAiiyB+6k
IN2kLSppvuCIyZk4VdTBrEhbiwALG7JlDKPODnkO6Zf6MXr1b9x21OTq0pp93ilt
DQQlSFQSgFs0gg804aiQKO9OblI4I2m3xBORouCe+vyR6u18PYEixRlIQFJT3wnb
trWJPZw/bQOEDtrCT7G1bh2Bmj+sayWKeBdQlLDYoqMBwMZOyYPuIQqaEUsrwQ2v
iPrhN4wiWNXmznjNDqC+n/8HvpZ20RNiE1CkelexAQKBgQD/OHV7IXEq5DIfQfy3
FW86zSDZmvy/ahLV9dNEGT+CeMmlKRPXVYOoeYR8sjxaHxfX2ci8pe4YTs0CKruX
vBQgKkKQ7h2tQFu+fTkVyqz3FeLny8LTzCLjIQPcGIgsam9c8tltlHkek32syoFH
kExVIJmossFN6FcMFxOoW/yh9QKBgQD+K+MJtzfWYyrYsO6JNNFpj9VVfB6pDA9b
umArCh29deJjEKZbqrFXgXaXLffpLUqDZRUEWgvcwrJ0CInmEph4hxlsgTeSBLHU
1xNt28Kq9OTGwbbd3EuqAyJv744lP0JIcm2Gv1QwXwaXzmdy14Mqh2Yqb15r570i
Pe9K5hezJQKBgQCe7R9q/1YjKVp00Hh34acT7KxqFPMSlxEHnz5hh39e1axrZnru
elezz4fKxoqCbB5C0WEI6CKtjFRo5wdN41Z8+RPegAiG3C7FHeEwSrcOXdigEuhN
Ty7iVKq8oaIaVmTmcmsmq3AItDtsH+YFFDwUPmqw/C8XPnkGFFCvZCibCQKBgQCW
dU5Jsw63ty5m5Z3e1MheL8m+d+ICeeQhjZtd/vgJ7l2b/QAtZUbjoPydk5Wcj7X7
P/wH/nHlNc/DhkZzTnC5cGfpZjiKFINclhCnSJ7c6mj/Cy7/+GdF9eMN1gYUIHVR
Q4N4b4wbsjTJ6mIshkzcARjGZ/TB9YVtXrJnaPuAjQKBgQC9vT9TL91ClnujIQ2A
/2vegMmOsagvU7Me078fMtSXBobBEVe20PM2LbOfj7e+rwLwre4Ky3w/nOufKz0c
t9sOMI7o6Vdtj4KLOMmFN9TgJZrNBpypPcYe4XoKhky3VFjxuKgaYIVhhNGGV8SP
p45ydRJ55Oyx1KEdAmXAmGHqrg==
-----END PRIVATE KEY-----
`

// Extracted from above with:
// openssl rsa -in myprivate.pem -pubout
const pkcs1v15Pub = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA/WXFZKauPWR2MAYKIJxp
UmwJ/qd/zgkKfeEKycmTWCr1nBkYQMDC0GYF8L9dJfqxPm9QP2yz16NAXcDBo6o/
3KBweveMmixxskVQ0BBQbbFCwc/yRf8CgqHPlPHvus/6z8wVEl2CN+RDniRYQSBD
O7Qu8xBZ4zIp2qijwoK3SLkXfbk6OzLMOzF277fBRvdmY3UXbkFt9PdtDVjLkUuA
CQ6eVColtdIomZl/Tgfh/Tvq+AA4C/kM0j4DWMF/P+FXAq+oWeP4Gbn66T2syA3V
5W/ziQhR2F+ytYAwOuGa4OFXqsiAZAYEqgMSJnOdPilrSlMq5BrQPeZ8dVitm8S3
aQIDAQAB
-----END PUBLIC KEY-----
`

// Generated with:
// openssl ecparam -genkey -name prime256v1 > ec_private.pem
// openssl pkcs8 -topk8 -in ec_private.pem  -nocrypt
const priv = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmrLtCpBdXgXLUr7o
nSUPfo3oXMjmvuwTOjpTulIBKlKhRANCAATH6KSpTFe6uXFmW1qNEFXaO7fWPfZt
pPZrHZ1cFykidZoURKoYXfkohJ+U/USYy8Sd8b4DMd5xDRZCnlDM0h37
-----END PRIVATE KEY-----
`

// Extracted from above with:
// openssl ec -in ec_private.pem -pubout
const pubStr = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx+ikqUxXurlxZltajRBV2ju31j32
baT2ax2dXBcpInWaFESqGF35KISflP1EmMvEnfG+AzHecQ0WQp5QzNId+w==
-----END PUBLIC KEY-----
`

// Generated with:
// openssl genpkey -algorithm ED25519 -out edprivate.pem
const ed25519Priv = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKjlXfR/VFvO9qM9+CG2qbuSM54k8ciKWHhgNwKTgqpG
-----END PRIVATE KEY-----
`

// Extracted from above with:
// openssl pkey -in edprivate.pem -pubout
const ed25519Pub = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAizWek2gKgMM+bad4rVJ5nc9NsbNOba0A0BNfzOgklRs=
-----END PUBLIC KEY-----
`

const pubWithTrailingNewLine = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx+ikqUxXurlxZltajRBV2ju31j32
baT2ax2dXBcpInWaFESqGF35KISflP1EmMvEnfG+AzHecQ0WQp5QzNId+w==
-----END PUBLIC KEY-----

`

func signData(t *testing.T, b []byte, pkey string) []byte {

	priv, err := cryptoutils.UnmarshalPEMToPrivateKey([]byte(pkey), cryptoutils.SkipPassword)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signature.LoadSigner(priv, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	signature, err := signer.SignMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func TestSignature_Verify(t *testing.T) {
	tests := []struct {
		name string
		priv string
		pub  string
	}{
		{
			name: "rsa",
			priv: pkcs1v15Priv,
			pub:  pkcs1v15Pub,
		},
		{
			name: "ec",
			priv: priv,
			pub:  pubStr,
		},
		{
			name: "ed25519",
			priv: ed25519Priv,
			pub:  ed25519Pub,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte("hey! this is my test data")
			sigBytes := signData(t, data, tt.priv)
			s, err := NewSignature(bytes.NewReader(sigBytes))
			if err != nil {
				t.Fatal(err)
			}

			pub, err := NewPublicKey(strings.NewReader(tt.pub))
			if err != nil {
				t.Fatal(err)
			}

			if err := s.Verify(bytes.NewReader(data), pub); err != nil {
				t.Errorf("Signature.Verify() error = %v", err)
			}

			// Now try with the canonical value
			cb, err := s.CanonicalValue()
			if err != nil {
				t.Error(err)
			}
			canonicalSig, err := NewSignature(bytes.NewReader(cb))
			if err != nil {
				t.Error(err)
			}
			if err := canonicalSig.Verify(bytes.NewReader(data), pub); err != nil {
				t.Errorf("Signature.Verify() error = %v", err)
			}

			pubKey, _ := cryptoutils.UnmarshalPEMToPublicKey([]byte(tt.pub))
			derKey, _ := cryptoutils.MarshalPublicKeyToDER(pubKey)
			digest := sha256.Sum256(derKey)
			expectedID := identity.Identity{Crypto: pubKey, Raw: derKey, Fingerprint: hex.EncodeToString(digest[:])}
			ids, err := pub.Identities()
			if err != nil {
				t.Fatal(err)
			}
			if len(ids) != 1 {
				t.Errorf("%v: too many identities, expected 1, got %v", tt.name, len(ids))
			}
			switch v := ids[0].Crypto.(type) {
			case *rsa.PublicKey:
				if tt.name != "rsa" {
					t.Fatalf("unexpected key, expected RSA, got %v", reflect.TypeOf(v))
				}
			case *ecdsa.PublicKey:
				if tt.name != "ec" {
					t.Fatalf("unexpected key, expected RSA, got %v", reflect.TypeOf(v))
				}
			case ed25519.PublicKey:
				if tt.name != "ed25519" {
					t.Fatalf("unexpected key, expected RSA, got %v", reflect.TypeOf(v))
				}
			default:
				t.Fatalf("unexpected key type, got %v", reflect.TypeOf(v))
			}
			if err := cryptoutils.EqualKeys(expectedID.Crypto, ids[0].Crypto); err != nil {
				t.Errorf("%v: public keys did not match: %v", tt.name, err)
			}
			if !reflect.DeepEqual(expectedID.Raw, ids[0].Raw) {
				t.Errorf("%v: raw identities did not match, expected %v, got %v", tt.name, expectedID.Raw, ids[0].Raw)
			}
			if expectedID.Fingerprint != ids[0].Fingerprint {
				t.Errorf("%v: fingerprints did not match, expected %v, got %v", tt.name, expectedID.Fingerprint, ids[0].Fingerprint)
			}
		})
	}
}

func TestSignature_VerifyFail(t *testing.T) {
	tests := []struct {
		name string
		priv string
		pub  string
	}{
		{
			name: "rsa",
			priv: pkcs1v15Priv,
			pub:  pkcs1v15Pub,
		},
		{
			name: "ec",
			priv: priv,
			pub:  pubStr,
		},
		{
			name: "ed25519",
			priv: ed25519Priv,
			pub:  ed25519Pub,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make some fake data, and tamper with the signature
			data := []byte("hey! this is my test data")
			sigBytes := signData(t, data, tt.priv)
			sigBytes[0]--
			s, err := NewSignature(bytes.NewReader(sigBytes))
			if err != nil {
				t.Fatal(err)
			}

			pub, err := NewPublicKey(strings.NewReader(tt.pub))
			if err != nil {
				t.Fatal(err)
			}

			if err := s.Verify(bytes.NewReader(data), pub); err == nil {
				t.Error("Signature.Verify() expected error!")
			}
		})
	}
}

func TestPublicKeyWithCertChain(t *testing.T) {
	rootCert, rootKey, _ := testutils.GenerateRootCa()
	subCert, subKey, _ := testutils.GenerateSubordinateCa(rootCert, rootKey)
	subjectURL, _ := url.Parse("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.1.1")
	leafCert, leafKey, _ := testutils.GenerateLeafCertWithSubjectAlternateNames(
		[]string{"example.com"}, []string{"subject@example.com"}, []net.IP{{1, 1, 1, 1}}, []*url.URL{subjectURL}, "oidc-issuer", subCert, subKey)

	pemCertChain, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, subCert, rootCert})
	if err != nil {
		t.Fatalf("unexpected error marshalling certificate chain: %v", err)
	}

	pub, err := NewPublicKey(bytes.NewReader(pemCertChain))
	if err != nil {
		t.Fatalf("unexpected error generating public key: %v", err)
	}
	if pub.certs == nil || !pub.certs[0].Equal(leafCert) || !pub.certs[1].Equal(subCert) || !pub.certs[2].Equal(rootCert) {
		t.Fatal("expected certificate chain to match provided certificate chain")
	}

	if !pub.CryptoPubKey().(*ecdsa.PublicKey).Equal(leafKey.Public()) {
		t.Fatal("expected public keys to match")
	}

	if !reflect.DeepEqual(pub.EmailAddresses(), leafCert.EmailAddresses) {
		t.Fatalf("expected matching subjects, expected %v, got %v", leafCert.EmailAddresses, pub.EmailAddresses())
	}

	var expectedSubjects []string
	expectedSubjects = append(expectedSubjects, leafCert.DNSNames...)
	expectedSubjects = append(expectedSubjects, leafCert.EmailAddresses...)
	expectedSubjects = append(expectedSubjects, leafCert.IPAddresses[0].String())
	expectedSubjects = append(expectedSubjects, leafCert.URIs[0].String())
	if !reflect.DeepEqual(pub.Subjects(), expectedSubjects) {
		t.Fatalf("expected matching subjects, expected %v, got %v", expectedSubjects, pub.Subjects())
	}

	digest := sha256.Sum256(leafCert.Raw)
	expectedID := identity.Identity{Crypto: leafCert, Raw: leafCert.Raw, Fingerprint: hex.EncodeToString((digest[:]))}
	ids, err := pub.Identities()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Errorf("too many identities, expected 1, got %v", len(ids))
	}
	if !ids[0].Crypto.(*x509.Certificate).Equal(expectedID.Crypto.(*x509.Certificate)) {
		t.Errorf("certificates did not match")
	}
	if !reflect.DeepEqual(expectedID.Raw, ids[0].Raw) {
		t.Errorf("raw identities did not match, expected %v, got %v", expectedID.Raw, ids[0].Raw)
	}
	if expectedID.Fingerprint != ids[0].Fingerprint {
		t.Errorf("fingerprints did not match, expected %v, got %v", expectedID.Fingerprint, ids[0].Fingerprint)
	}

	canonicalValue, err := pub.CanonicalValue()
	if err != nil {
		t.Fatalf("unexpected error fetching canonical value: %v", err)
	}
	if !reflect.DeepEqual(canonicalValue, pemCertChain) {
		t.Fatalf("expected canonical value %v, got %v", pemCertChain, canonicalValue)
	}

	// Generate signature to verify
	data := []byte("test")
	signer, err := signature.LoadSigner(leafKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes, err := signer.SignMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSignature(bytes.NewReader(sigBytes))
	if err != nil {
		t.Fatalf("unexpected error generating signature: %v", err)
	}
	err = s.Verify(bytes.NewReader(data), pub)
	if err != nil {
		t.Fatalf("unexpected error verifying signature, %v", err)
	}

	// Verify works with expired certificate
	leafCert, leafKey, _ = testutils.GenerateExpiredLeafCert("subject@example.com", "oidc-issuer", subCert, subKey)
	pemCertChain, _ = cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, subCert, rootCert})
	pub, _ = NewPublicKey(bytes.NewReader(pemCertChain))
	signer, _ = signature.LoadSigner(leafKey, crypto.SHA256)
	sigBytes, _ = signer.SignMessage(bytes.NewReader(data))
	s, _ = NewSignature(bytes.NewReader(sigBytes))
	err = s.Verify(bytes.NewReader(data), pub)
	if err != nil {
		t.Fatalf("unexpected error verifying signature with expired certificate: %v", err)
	}

	// Verify error with invalid chain
	pemCertChain, _ = cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, rootCert})
	pub, _ = NewPublicKey(bytes.NewReader(pemCertChain))
	signer, _ = signature.LoadSigner(leafKey, crypto.SHA256)
	sigBytes, _ = signer.SignMessage(bytes.NewReader(data))
	s, _ = NewSignature(bytes.NewReader(sigBytes))
	err = s.Verify(bytes.NewReader(data), pub)
	if err == nil || !strings.Contains(err.Error(), "x509: certificate signed by unknown authority") {
		t.Fatalf("expected error verifying signature, got %v", err)
	}

	// Verify works with chain without intermediate
	leafCert, leafKey, _ = testutils.GenerateLeafCert("subject@example.com", "oidc-issuer", nil, rootCert, rootKey)
	pemCertChain, _ = cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, rootCert})
	pub, _ = NewPublicKey(bytes.NewReader(pemCertChain))
	signer, _ = signature.LoadSigner(leafKey, crypto.SHA256)
	sigBytes, _ = signer.SignMessage(bytes.NewReader(data))
	s, _ = NewSignature(bytes.NewReader(sigBytes))
	err = s.Verify(bytes.NewReader(data), pub)
	if err != nil {
		t.Fatalf("unexpected error verifying signature, %v", err)
	}

	// Verify error with long chain
	chain := []*x509.Certificate{}
	for i := 0; i < 11; i++ {
		chain = append(chain, leafCert)
	}
	pemCertChain, _ = cryptoutils.MarshalCertificatesToPEM(chain)
	_, err = NewPublicKey(bytes.NewReader(pemCertChain))
	if err == nil || !strings.Contains(err.Error(), "too many certificates specified in PEM block") {
		t.Fatalf("expected error with long certificate chain, got %v", err)
	}

	// Verify public key with extra trailing newline is parsed OK
	key, err := NewPublicKey(strings.NewReader(pubWithTrailingNewLine))
	if err != nil {
		t.Fatalf("unexpected error parsing public key with extra trailing newline: %v", err)
	}
	canonicalKeyBytes, err := key.CanonicalValue()
	if err != nil {
		t.Fatalf("unexpected error canonicalizing public key with extra trailing newline: %v", err)
	}

	if !bytes.Equal([]byte(pubStr), canonicalKeyBytes) {
		t.Fatalf("expected canonical value to match original without extra trailing new line")
	}
}
