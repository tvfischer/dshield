FROM ubuntu:18.04

RUN apt-get update && apt-get install -y \
    authbind \
    build-essential \
    curl \
    dialog \
    gcc \
    git \ 
    jq \
    libffi-dev \
    libmariadb-dev-compat \
    libmpc-dev \
    libmpfr-dev \
    libpython3-dev \
    libssl-dev \
    libswitch-perl \
    libwww-perl \
    net-tools \
    python3-pip \
    python3-requests \
    python3-dev \
    python3-minimal \
    python3-requests \
    python3-urllib3 \
    python3-virtualenv \
    randomsound \
    rng-tools \
    sqlite3 \
    unzip \
    wamerican \
    zip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/dshield
COPY . .

# CMD ["bin/install.sh"]
# EXPOSE 2223
# EXPOSE 2222
# EXPOSE 8000
 
