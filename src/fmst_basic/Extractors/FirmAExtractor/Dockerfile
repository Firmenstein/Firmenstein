# Firmenstein Development Environment
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

# Install basic packages
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
    sudo \
    binutils \
    coreutils \
    python3 \
    python3-pip \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release

# Install additional packages for firmware analysis
RUN apt-get install -y \
    busybox-static \
    bash-static \
    fakeroot \
    dmsetup \
    kpartx \
    netcat-openbsd \
    python3-psycopg2 \
    snmp \
    uml-utilities \
    util-linux \
    vlan \
    mtd-utils \
    arj \
    lhasa \
    p7zip \
    p7zip-full \
    cabextract \
    fusecram \
    cramfsswap \
    squashfs-tools \
    sleuthkit \
    default-jdk \
    cpio \
    lzop \
    lzma \
    srecord \
    zlib1g-dev \
    liblzma-dev \
    liblzo2-dev \
    libpq-dev

# RUN update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-18 100 && \
#     update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100 && \
#     update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-18 100 && \
#     update-alternatives --install /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-18 100 && \
#     update-alternatives --install /usr/bin/llvm-ar llvm-ar /usr/bin/llvm-ar-18 100 && \
#     update-alternatives --install /usr/bin/llvm-dis llvm-dis /usr/bin/llvm-dis-18 100 && \
#     update-alternatives --install /usr/bin/opt opt /usr/bin/opt-18 100

RUN ln -sf /usr/bin/python3 /usr/bin/python

# Create firmae user with sudo privileges
RUN useradd -m firmae && \
    usermod -aG sudo firmae && \
    echo "firmae ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
USER firmae
RUN mkdir -p /home/firmae/extractor
WORKDIR /home/firmae/extractor

# Upgrade pip and install Python packages
RUN python3 -m pip install --upgrade pip setuptools wheel coloredlogs

RUN pip3 install \
    requests \
    urllib3 \
    tqdm \
    jsonschema \
    pyyaml \
    toml \
    pytest \
    pytest-cov \
    python-magic

# Create python symlink and install binwalk
RUN wget https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v2.3.4.tar.gz && \
    tar -xf v2.3.4.tar.gz && \
    rm -rf v2.3.4.tar.gz && \
    cd binwalk-2.3.4 && \
    sed -i 's/^install_ubireader//g' deps.sh && \
    chmod +x deps.sh

RUN cd binwalk-2.3.4 && \
    sudo python3 setup.py install && \
    echo 'y' | sudo ./deps.sh

# Copy the extractor script
COPY ./FirmAExtractor.py /home/firmae/extractor/FirmAExtractor.py

RUN mkdir -p /home/firmae/extractor/workdir

SHELL ["/bin/bash", "-c"]

CMD ["/bin/bash"]