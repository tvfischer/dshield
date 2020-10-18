FROM ubuntu:20.04
LABEL maintainer="Thomas Fischer @Fvt"
LABEL description="SANS ISC dshield honeypot base image"

# *********** Installing Prerequisites ***************
# -qq : No output except for errors
RUN apt-get update -qq && apt-get install -qqy \
    authbind \
    build-essential \
    curl \
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
    rng-tools \
    sqlite3 \
    unzip \
    wamerican \
    zip \
  # ********* do we really need the following packages?
    dialog \
    randomsound \       
  # ********* Clean ****************************
    && apt-get -qy clean \
       autoremove \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/dshield
COPY . /usr/src/dshield

# CMD ["bin/install.sh"]
# EXPOSE 2223
# EXPOSE 2222
# EXPOSE 8000
 
