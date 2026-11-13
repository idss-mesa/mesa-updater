# Cut from idss-mesa/cli gpu/Dockerfile for tests/test_sbom_from_locks.py.
# BASE_IMAGE is the CPU image built by the same release, so it has no digest
# here; as a 'base' row this file records only the pinned build-stage image.
ARG BASE_IMAGE=harbor.cyverse.org/vice/mesa-cli:latest
# Build stage only (compiles cuda-probe); index digest.
ARG CUDA_PROBE_IMAGE=ubuntu:24.04@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5

# cuda-probe: tiny glibc-only helper used by mesa-gpu-env.sh and mesa-gpu-check
FROM ${CUDA_PROBE_IMAGE} AS cuda-probe
RUN gcc -O2 -Wall -o /cuda-probe /src/cuda-probe.c -ldl

FROM ${BASE_IMAGE}

ARG TORCH_INDEX_URL=https://download.pytorch.org/whl/cu126
ARG TORCH_VERSION=2.14.0
ARG TORCHVISION_VERSION=0.29.0

ARG CUDA_COMPAT_VERSION=13.4

# Ollama (pinned, sha256-checked; never ollama.com/install.sh: with no
# nvidia-smi at build time it bakes the cuda-drivers userspace into the image).
# The real binary is ollama.bin; /usr/local/bin/ollama is the compat wrapper.
# Last of the heavy layers: bumping OLLAMA_* re-runs only this 2.2 GB layer.
ARG OLLAMA_VERSION=0.40.11
ARG OLLAMA_SHA256=7bedab90dd122661be78798e9f0edf37fccf0cccf2699d2c58ea1a3afdc04b6d
RUN curl -fsSL -o /tmp/ollama.tar.zst "https://github.com/ollama/ollama/releases/download/v${OLLAMA_VERSION}/ollama-linux-amd64.tar.zst" && \
    echo "${OLLAMA_SHA256}  /tmp/ollama.tar.zst" | sha256sum -c - && \
    zstd -dc /tmp/ollama.tar.zst | tar -xf - -C /usr/local && rm -f /tmp/ollama.tar.zst && \
    mv /usr/local/bin/ollama /usr/local/bin/ollama.bin
