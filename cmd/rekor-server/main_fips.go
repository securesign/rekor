//go:build fips

// RHTAS FIPS - DO NOT REMOVE

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

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/sigstore/rekor/cmd/rekor-server/app"
)

func init() {
	data, err := os.ReadFile("/proc/sys/crypto/fips_enabled")
	if err != nil {
		fmt.Println("FIPS binary: could not read /proc/sys/crypto/fips_enabled")
		return
	}
	if strings.TrimSpace(string(data)) == "1" {
		fmt.Println("Rekor server is running in FIPS mode")
	} else {
		fmt.Println("WARNING: FIPS binary running on non-FIPS enabled system")
	}
}

func main() {
	app.Execute()
}
