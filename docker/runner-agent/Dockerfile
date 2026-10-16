ARG RUNNER_BUILDER_IMAGE=firmenstein/runtime-builder:rust1.98-py312-bookworm
FROM ${RUNNER_BUILDER_IMAGE}
RUN apt-get update && apt-get install --no-install-recommends -y \
 sudo tini git curl wget jq file ripgrep iproute2 iptables \
 util-linux procps psmisc netcat-openbsd socat tcpdump strace ltrace gdb gdb-multiarch \
 unzip xz-utils ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --shell /bin/bash runner \
 && echo 'runner ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/runner \
 && chmod 440 /etc/sudoers.d/runner \
 && chmod o+x /root \
 && chmod -R a+rwX "$CARGO_HOME" "$RUSTUP_HOME"
RUN cd /tmp \
 && curl -fsSLO https://nodejs.org/dist/v22.14.0/node-v22.14.0-linux-x64.tar.xz \
 && curl -fsSLO https://nodejs.org/dist/v22.14.0/SHASUMS256.txt \
 && grep ' node-v22.14.0-linux-x64.tar.xz$' SHASUMS256.txt | sha256sum -c - \
 && tar -xJf node-v22.14.0-linux-x64.tar.xz --strip-components=1 -C /usr/local \
 && rm node-v22.14.0-linux-x64.tar.xz SHASUMS256.txt
RUN python3.12 -m venv /opt/venv
ENV PATH=/opt/venv/bin:${CARGO_HOME}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    FMST_RUNNER_CONTAINER=1
COPY requirements.txt /opt/fmst-requirements.txt
RUN pip install --no-cache-dir -r /opt/fmst-requirements.txt
# Exercise the same explicit interpreter used by privileged task commands.
RUN runuser -u runner -- sudo --preserve-env=PYTHONPATH /opt/venv/bin/python \
 -c "import os, pydantic, sys; assert sys.version_info[:2] == (3, 12); assert sys.prefix == '/opt/venv'; assert callable(os.setns) and callable(os.unshare)"
RUN npm install -g agent-browser@0.26.0
COPY install-browser.sh /opt/fmst-install-browser.sh
RUN apt-get update \
 && if apt-cache show libasound2t64 >/dev/null 2>&1; then \
      browser_libraries='libatk1.0-0t64 libatk-bridge2.0-0t64 libcups2t64 libasound2t64 libatspi2.0-0t64'; \
    else browser_libraries='libatk1.0-0 libatk-bridge2.0-0 libcups2 libasound2 libatspi2.0-0'; fi \
 && apt-get install --no-install-recommends -y \
 $browser_libraries libnss3 libdrm2 libxkbcommon0 \
 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 \
 libpango-1.0-0 libcairo2 fonts-liberation \
 && runuser -u runner -- sh /opt/fmst-install-browser.sh \
 && rm -rf /root/.npm /root/.cache /var/lib/apt/lists/*
WORKDIR /task/work
RUN pip install --no-cache-dir jinja2
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/venv/bin/python", "-m", "fmst_analyzer.runner.task.init"]
