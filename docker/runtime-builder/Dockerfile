ARG GUESTWEAVE_BUILDER_IMAGE=rust:1.98.0-bookworm
FROM python:3.12-slim-bookworm AS python
FROM ${GUESTWEAVE_BUILDER_IMAGE}

# Both stages use Bookworm/glibc. Keep the distribution's /usr/bin/python3
# for OS utilities; Firmenstein uses the official Python under /usr/local.
COPY --from=python /usr/local/ /usr/local/

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl gnupg \
    && curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
       | gpg --dearmor -o /usr/share/keyrings/llvm-snapshot.gpg \
    && . /etc/os-release \
    && echo "deb [signed-by=/usr/share/keyrings/llvm-snapshot.gpg] https://apt.llvm.org/${VERSION_CODENAME}/ llvm-toolchain-${VERSION_CODENAME}-22 main" \
       > /etc/apt/sources.list.d/llvm22.list \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
        binutils build-essential clang cmake libclang-dev libglib2.0-dev \
        libpixman-1-dev llvm-22 make ninja-build pkg-config \
        libbz2-1.0 libdb5.3 libexpat1 libffi8 liblzma5 libncursesw6 \
        libreadline8 libsqlite3-0 libssl3 libuuid1 zlib1g \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && ldconfig

RUN python3.12 -c "import bz2, ctypes, lzma, os, readline, sqlite3, ssl, sys; assert sys.version_info[:2] == (3, 12); assert callable(os.setns) and callable(os.unshare)"

RUN rustup component add --toolchain 1.98.0 rustfmt clippy
ENV RUSTUP_TOOLCHAIN=1.98.0 LLVM_CONFIG_PATH=/usr/bin/llvm-config-22

WORKDIR /workspace/project
