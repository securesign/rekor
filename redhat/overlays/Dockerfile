#
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM registry.access.redhat.com/ubi9/go-toolset@sha256:c3a9c5c7fb226f6efcec2424dd30c38f652156040b490c9eca5ac5b61d8dc3ca AS builder
ENV APP_ROOT=/opt/app-root
ENV GOPATH=$APP_ROOT

WORKDIR $APP_ROOT/src/
ADD go.mod go.sum $APP_ROOT/src/
RUN go mod download

# Add source code
ADD ./cmd/ $APP_ROOT/src/cmd/
ADD ./pkg/ $APP_ROOT/src/pkg/

ARG SERVER_LDFLAGS
RUN go build -ldflags "${SERVER_LDFLAGS}" ./cmd/rekor-server
RUN CGO_ENABLED=0 go build -gcflags "all=-N -l" -ldflags "${SERVER_LDFLAGS}" -o rekor-server_debug ./cmd/rekor-server
RUN go test -c -ldflags "${SERVER_LDFLAGS}" -cover -covermode=count -coverpkg=./... -o rekor-server_test ./cmd/rekor-server

# debug compile options & debugger
FROM registry.access.redhat.com/ubi9/go-toolset@sha256:c3a9c5c7fb226f6efcec2424dd30c38f652156040b490c9eca5ac5b61d8dc3ca as debug
RUN go install github.com/go-delve/delve/cmd/dlv@v1.8.0

# overwrite server and include debugger
COPY --from=builder /opt/app-root/src/rekor-server_debug /usr/local/bin/rekor-server

FROM registry.access.redhat.com/ubi9/go-toolset@sha256:c3a9c5c7fb226f6efcec2424dd30c38f652156040b490c9eca5ac5b61d8dc3ca as test

USER root

# Extract the x86_64 minisign binary to /usr/local/bin/
RUN curl -LO https://github.com/jedisct1/minisign/releases/download/0.11/minisign-0.11-linux.tar.gz && \
    tar -xzf minisign-0.11-linux.tar.gz minisign-linux/x86_64/minisign -O > /usr/local/bin/minisign && \
    chmod +x /usr/local/bin/minisign && \
    rm minisign-0.11-linux.tar.gz

# Create test directory
RUN mkdir -p /var/run/attestations && \
    touch /var/run/attestations/attestation.json && \
    chmod 777 /var/run/attestations/attestation.json

# overwrite server with test build with code coverage
COPY --from=builder /opt/app-root/src/rekor-server_test /usr/local/bin/rekor-server

# Multi-Stage production build
FROM registry.access.redhat.com/ubi9/ubi-minimal@sha256:3e313209ac617a92b50350286752311d99ea2dafc429ef0e5311889294b0bc21 as deploy

LABEL description="Rekor aims to provide an immutable, tamper-resistant ledger of metadata generated within a software project’s supply chain."
LABEL io.k8s.description="Rekor-Server provides a tamper resistant ledger."
LABEL io.k8s.display-name="Rekor-Server container image for Red Hat Trusted Signer"
LABEL io.openshift.tags="rekor-server trusted-signer"
LABEL summary="Provides the rekor Server binary for running Rekor-Server"
LABEL com.redhat.component="rekor-server"

# Retrieve the binary from the previous stage
COPY --from=builder /opt/app-root/src/rekor-server /usr/local/bin/rekor-server

# Set the binary as the entrypoint of the container
ENTRYPOINT ["rekor-server"]