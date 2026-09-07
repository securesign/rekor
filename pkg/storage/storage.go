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

package storage

import (
	"context"
	"crypto/fips140"
	"errors"
	"fmt"

	"github.com/sigstore/rekor/pkg/log"

	"github.com/spf13/viper"
	"gocloud.dev/blob"

	// Blank imports to register storage
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/memblob"
	_ "gocloud.dev/blob/s3blob"
)

type AttestationStorage interface {
	StoreAttestation(ctx context.Context, key string, attestation []byte) error
	FetchAttestation(ctx context.Context, key string) ([]byte, error)
}

func NewAttestationStorage() (AttestationStorage, error) {
	if url := viper.GetString("attestation_storage_bucket"); url != "" {
		log.Logger.Infof("Configuring attestation storage at %s", url)
		bucket, err := blob.OpenBucket(context.Background(), url)
		if err != nil {
			return nil, err
		}
		return &Blob{
			bucket: bucket,
		}, nil
	}
	return nil, errors.New("no storage configured")
}

type Blob struct {
	bucket *blob.Bucket
}

func (b *Blob) StoreAttestation(ctx context.Context, key string, attestation []byte) error {
	log.ContextLogger(ctx).Infof("storing attestation at %s", key)
	// RHTAS FIPS - DO NOT REMOVE
	// ========================================
	// gocloud.dev/blob/fileblob computes MD5 for sidecar metadata on every write.
	// MD5 is not used for integrity or authentication here — it is a non-cryptographic
	// content identifier. WithoutEnforcement prevents a panic under fips140=only
	// without weakening any cryptographic operation.
	var writeErr error
	fips140.WithoutEnforcement(func() {
		w, err := b.bucket.NewWriter(ctx, key, nil)
		if err != nil {
			writeErr = err
			return
		}
		if _, err := w.Write(attestation); err != nil {
			_ = w.Close()
			writeErr = err
			return
		}
		writeErr = w.Close()
	})
	return writeErr
	// ========================================
}

func (b *Blob) FetchAttestation(ctx context.Context, key string) ([]byte, error) {
	log.ContextLogger(ctx).Infof("fetching attestation %s", key)
	// RHTAS FIPS - DO NOT REMOVE
	// ========================================
	// gocloud.dev/blob/fileblob may use MD5 when reading blob attributes.
	// MD5 here is a non-cryptographic content identifier, not used for
	// integrity or authentication. Same rationale as StoreAttestation.
	var data []byte
	var fetchErr error
	fips140.WithoutEnforcement(func() {
		exists, err := b.bucket.Exists(ctx, key)
		if err != nil {
			fetchErr = err
			return
		}
		if !exists {
			fetchErr = fmt.Errorf("attestation %v does not exist", key)
			return
		}
		data, fetchErr = b.bucket.ReadAll(ctx, key)
	})
	return data, fetchErr
	// ========================================
}
