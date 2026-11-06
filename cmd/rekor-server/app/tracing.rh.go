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

// This file carries a downstream-only (RHTAS) addition: OpenTelemetry tracing
// startup for the rekor-server command. It is deliberately kept in a dedicated
// file so the customization is easy to identify and causes minimal conflicts in
// files maintained upstream.

package app

import (
	"context"
	"fmt"

	"github.com/securesign/sigstore-observability-instrumentation/tracing"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"sigs.k8s.io/release-utils/version"
)

func init() {
	tracingConfig := tracing.DefaultConfig()
	tracingConfig.AddFlags(rootCmd.PersistentFlags())
	// Rebind viper: these flags are registered after the BindPFlags call in
	// root.go's init(), which runs before this file's init().
	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		log.Logger.Fatal(err)
	}

	serveCmd.PreRunE = func(_ *cobra.Command, _ []string) error {
		shutdownTracing, err := tracing.Setup(
			context.Background(),
			tracing.ConfigFromGetter(viper.GetViper()),
			tracing.WithServiceName("rekor-server"),
			tracing.WithServiceVersion(version.GetVersionInfo().GitVersion),
		)
		if err != nil {
			return fmt.Errorf("failed to initialize tracing: %w", err)
		}

		// Register cleanup only after successful setup so the shutdown function
		// stays local. OnFinalize also runs when command execution returns an
		// error. Existing log.Fatal calls bypass this cleanup, matching the
		// previous defer-based behavior.
		cobra.OnFinalize(func() {
			if err := shutdownTracing(context.Background()); err != nil {
				log.Logger.Errorf("error shutting down tracing: %v", err)
			}
		})
		return nil
	}
}
