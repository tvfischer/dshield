FROM ubuntu:20.04
LABEL maintainer="Thomas Fischer @Fvt"
LABEL description="SANS ISC dshield honeypot base image"
LABEL version="75"

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
  # ********* Docker specific additional packages
    iproute2 \
    systemctl \     
  # ********* Clean ****************************
    && apt-get -qy clean \
       autoremove \
    && rm -rf /var/lib/apt/lists/* 

WORKDIR /usr/src/dshield
COPY . /usr/src/dshield

ENV TARGETDIR="/srv"
ENV DSHIELDDIR="${TARGETDIR}/dshield"
ENV COWRIEDIR="${TARGETDIR}/cowrie"
ENV TXTCMDS=${COWRIEDIR}/share/cowrie/txtcmds
ENV LOGDIR="${TARGETDIR}/log"
ENV WEBDIR="${TARGETDIR}/www"
ENV SSHHONEYPORT=2222
ENV TELNETHONEYPORT=2223
ENV WEBHONEYPORT=8000
ENV SSHREDIRECT="22"
ENV TELNETREDIRECT="23 2323"
ENV WEBREDIRECT="80 8080 7547 5555 9000"
ENV HONEYPORTS="${SSHHONEYPORT} ${TELNETHONEYPORT} ${WEBHONEYPORT}"

# ********* Now we run the dshield install script (docker version) inside the container
# ********* Future may move alot of the install parts to 
RUN bin/install-docker.sh


# CMD ["bin/install.sh"]
# EXPOSE 2223
# EXPOSE 2222
# EXPOSE 8000
 
EXPOSE ${HONEYPORTS}