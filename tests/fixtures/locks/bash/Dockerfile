# Cut from idss-mesa/cli bash/Dockerfile for tests/test_sbom_from_locks.py:
# the pinned-download ARGs and two of the RUN steps that use them. The base
# image is digest-pinned through ARG BASE_IMAGE (the real file is not yet).
ARG BASE_IMAGE=quay.io/jupyter/minimal-notebook:2026-11-09@sha256:29076b0b96c954a16b813cc5c4230f248711ef1d7528cb1208b82397e86a8b52
FROM ${BASE_IMAGE}

USER root

# Target architecture set by buildx: amd64 or arm64
ARG TARGETARCH

# ---------------------------------------------------------------------------
# Pinned, checksum-verified downloads (2026-10 security review). Bump the
# version AND its hash together: a mismatch fails the build. Hashes are the
# sha256 of the upstream release asset (or, for Node, nodejs.org's own
# SHASUMS256.txt, fetched and checked at build time).
# ---------------------------------------------------------------------------
ARG TINI_VERSION=0.19.0
ARG TINI_SHA256_AMD64=93dcc18adc78c65a028a84799ecf8ad40c936fdfc5f2a57b1acda5a8117fa82c
ARG TINI_SHA256_ARM64=07952557df20bfd2a95f9bef198b445e006171969499a1d361bd9e6f8e5e0e81
ARG GO_VERSION=1.27.3
ARG GO_SHA256_AMD64=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
ARG GO_SHA256_ARM64=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49
ARG TTYD_VERSION=1.7.7
ARG TTYD_SHA256_X86_64=8a217c968aba172e0dbf3f34447218dc015bc4d5e59bf51db2f2cd12b7be4f55
ARG TTYD_SHA256_AARCH64=b38acadd89d1d396a0f5649aa52c539edbad07f4bc7348b27b4f4b7219dd4165
ARG NODE_VERSION=22.23.4
ARG GOCMD_VERSION=v0.12.5
ARG GOCMD_SHA256_AMD64=af551f8cb2f3f5df63fb3a8eb1bf605c7f27e50ec10283a5375190239db9f57a
ARG GOCMD_SHA256_ARM64=2741c2a2c894ad156b63ea7ca16f5e7931662bd16e6331d4fbcfea904cc76143
ARG GCM_VERSION=2.7.3
ARG GCM_SHA256_X64=a5431e1b6f25aa8b424e747d880f86e74c739ad52e72c924a7b1a25d87ac7e72
ARG GCM_SHA256_ARM64=f5995901ef3a2ffc4442e4a9a92c8dfdc8f1df1affe8ef1d037b7ad3302b923b
ARG AWSCLI_VERSION=2.38.5
ARG AWSCLI_SHA256_X86_64=5def7d1b7e55d892f9a381bb2cb2081a685712464be0d36d5d706af0ac48d0d3
ARG AWSCLI_SHA256_AARCH64=07711a936e9d271045ab937d2c2c5390c25f419e4ba9e25adb9e996031e3f6be
ARG DUCKDB_SHA256_AMD64=c6507206baf7793c6013dbd82368469a45f20dc0e17a6f92f204602f652ed2bc
ARG DUCKDB_SHA256_ARM64=859e1875d2a9515fbb4bf8871061437a14af82320da68c753f094c4b776348fe
# npm registry packages are version-pinned; npm verifies the registry integrity hash
ARG CLAUDE_CODE_VERSION=2.1.310
ARG CODEX_VERSION=0.164.0
ARG CCR_VERSION=3.1.3
ARG MCP_FS_VERSION=2.0.1
ARG OPENCODE_VERSION=1.19.4
ARG GOOSE_VERSION=1.56.0

# Install Go (pinned + sha256; Go >= 1.25.7 fixes CVE-2025-68121 in every binary built here)
RUN GO_SHA256=$([ "$TARGETARCH" = "arm64" ] && echo "$GO_SHA256_ARM64" || echo "$GO_SHA256_AMD64") && \
    curl -fsSL -o /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz" && \
    echo "${GO_SHA256}  /tmp/go.tgz" | sha256sum -c - && \
    tar -xz -C /usr/local -f /tmp/go.tgz && rm -f /tmp/go.tgz

# Install GoCommands (pinned + sha256; it is NOT self-upgraded from ~/.bashrc any more)
# https://learning.cyverse.org/ds/gocommands/
RUN GOCMD_SHA256=$([ "$TARGETARCH" = "arm64" ] && echo "$GOCMD_SHA256_ARM64" || echo "$GOCMD_SHA256_AMD64") && \
    curl -fsSL -o /tmp/gocmd.tgz "https://github.com/cyverse/gocommands/releases/download/${GOCMD_VERSION}/gocmd-${GOCMD_VERSION}-linux-${TARGETARCH}.tar.gz" && \
    echo "${GOCMD_SHA256}  /tmp/gocmd.tgz" | sha256sum -c - && \
    tar -xz -C /usr/local/bin -f /tmp/gocmd.tgz && rm -f /tmp/gocmd.tgz && gocmd --version

ARG DUCKDB_VERSION=2.0.0
