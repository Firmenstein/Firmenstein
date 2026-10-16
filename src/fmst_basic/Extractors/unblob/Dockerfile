# Firmenstein Development Environment
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    vim \
    tree \
    unzip \
    zip \
    tar \
    gzip \
    bzip2 \
    xz-utils \
    build-essential \
    autoconf \
    automake \
    libtool \
    nmap \
    binutils \
    coreutils \
    python3 \
    python3-pip \
    liblzma-dev \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release

# install unblob dependencies
RUN apt install -y \
    android-sdk-libsparse-utils \
    e2fsprogs \
    p7zip-full \
    unar \
    zlib1g-dev \
    liblzo2-dev \
    lzop \
    lziprecover \
    libhyperscan-dev \
    zstd \
    lz4


# add squashfs support for unblob
RUN curl -L -o sasquatch_1.0.deb "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-5/sasquatch_1.0_$(dpkg --print-architecture).deb" \
    && dpkg -i sasquatch_1.0.deb \
    && rm sasquatch_1.0.deb

# install e2fsprogs for unblob
RUN curl -L -o e2fsprogs_1.47.0-3.ok2.deb "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/e2fsprogs_1.47.0-3.ok2_$(dpkg --print-architecture).deb" \
    && curl -L -o libext2fs2_1.47.0-3.ok2.deb "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/libext2fs2_1.47.0-3.ok2_$(dpkg --print-architecture).deb" \
    && curl -L -o libss2_1.47.0-3.ok2.deb "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/libss2_1.47.0-3.ok2_$(dpkg --print-architecture).deb" \
    && dpkg -i libext2fs2_1.47.0-3.ok2.deb libss2_1.47.0-3.ok2.deb \
    && dpkg -i e2fsprogs_1.47.0-3.ok2.deb \
    && rm -f libext2fs2_1.47.0-3.ok2.deb libss2_1.47.0-3.ok2.deb e2fsprogs_1.47.0-3.ok2.deb

RUN python3 -m pip install --upgrade pip setuptools wheel

# Build the narrowly patched SquashFS 3 recovery extractor used for vendor
# images whose directories contain duplicate or unsorted entries.
COPY squashfs3-unsorted-directory.patch /tmp/squashfs3-unsorted-directory.patch
RUN git clone https://github.com/plougher/squashfs-tools.git /tmp/squashfs-tools \
    && cd /tmp/squashfs-tools \
    && git checkout 52992df017ea9f80e37012947538249547a0d048 \
    && git apply /tmp/squashfs3-unsorted-directory.patch \
    && make -C squashfs-tools unsquashfs XZ_SUPPORT=1 LZO_SUPPORT=1 LZ4_SUPPORT=0 ZSTD_SUPPORT=0 \
    && install -m 0755 squashfs-tools/unsquashfs /usr/local/bin/unsquashfs-recovery \
    && rm -rf /tmp/squashfs-tools /tmp/squashfs3-unsorted-directory.patch

# create a non-root user named "unblob" for using unblob
RUN useradd -m unblob

# install unblob for the unblob user
USER unblob
RUN python3 -m pip install --user unblob==25.5.26

# add ~/.local/bin into PATH
ENV PATH="/home/unblob/.local/bin:${PATH}"

RUN mkdir -p /home/unblob/analysis

WORKDIR /home/unblob/analysis

CMD ["unblob", "--show-external-dependencies"]
