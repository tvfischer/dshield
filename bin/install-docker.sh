#!/bin/bash
####
#
#  Install Script for Docker container version of dshield
#  This script only deploys the requried dshield software. It will do basic configuration
#    but the dshield-entrypoint will finalise and launch the services
#  
#  exit codes:
#  9 - install error
#  5 - user cancel
#
####

###########################################################
## CONFIG SECTION
###########################################################

# version 2020/09/21 01

readonly myversion=74

#
# Major Changes (for details see Github):
#
# - V75 (Fvt)
#   - Changes to support a full Dockerfile and docker container deployment
#   - Added a specific docker install component
#
# - V74 (Freek)
#   - webpy port to Python3 and bug fix
#
# - V73 (Johannes)
#   - misc improvements to installer and documentation
#
# - V72 (Johannes)
#   - version incremented for tech tuesday
#
# - V71 (Johannes)
#   - upgraded cowrie version
#   - moved to smaller cowrie zip file
#   - updated prep.sh to match new cowrie version
#
# - V70 (Johannes)
#   - added prep.sh
#   - Ubuntu 20.04 support
#
# - V65 (Johannes)
#   - bug fixes, in particular in fwlogparser
#   - enabled debug logging in install.sh
#
# - V64 (Johannes)
#   - cleanup / typos
#
# - V63 (Johannes)
#   - changed to integer versions for easier handling
#   - added "update" mode for non-interactive updates
#
# - V0.62 (Johannes)
#   - modified fwlogparser.py to work better with large logs
#     it will now only submit logs up to one day old, and not
#     submit more than 100,000 lines per run (it should run
#     twice an house). If there are more log, than it will skip
#     logs on future runs.
#
# - V0.61 (Johannes)
#   - redoing multiline dialogs to be more robust
#   - adding external honeypot IP to dshield.ini
#
# - V0.60 (Johannes)
#   - fixed a bug that prevented SSH logins to cowrie
#   - upgraded to cowrie 2.0.2 (latest)
#   - improved compatiblity with Ubuntu 18.04
#
# - V0.50 (Johannes)
#   - adding support for Raspbian 10 (buster)
#
# - V0.49 (Johannes)
#   - new cowrie configuration from scratch vs. using the template
#     that is included with cowrie
#
# - V0.48 (Johannes)
#   - fixed dshield logging in cowrie
#   - remove MySQL
#   - made local IP exclusion "wider"
#   - added email to configuration file for convinience
#
# - V0.47
#   - many small changes, see GitHub
#
# - V0.46 (Gebhard)
#   - removed obsolete suff (already commented out)
#   - added comments
#   - some cleanup
#   - removed mini http
#   - added multicast disable rule to ignore multicasts for dshield logs
#   - dito broadcasts to 255.255.255.255
#   - ask if automatic updates are OK
#
# - V0.45 (Johannes)
#    - enabled web honeypot
#
# - V0.44 (Johannes)
#   - enabled telnet in cowrie
#
# - V0.43 (Gebhard)
#   - revised cowrie installation to reflect current instructions
#
# - V0.42
#   - quick fix for Johannes' experiments with new Python code
#     (create dshield.ini with default values)
#   - let user choose between old, working and experimental stuff
#     (idea: copy all stuff but only activate that stuff the user chose
#      so the user can experiment even if he chose mature)
#
# - V0.41
#   - corrected firewall logging to dshield: in prior versions
#     the redirected ports would be logged and reported, not
#     the ports from the original requests (so ssh connection
#     attempts were logged as attempts to connect to 2222)
#   - changed firewall rules: access only allowed to honeypot ports
#   - some configuration stuff
#   - some bugfixes
#
# - V0.4
#   - major additions and rewrites (e.g. added logging)
#
#

INTERACTIVE=0
FAST=0

# parse command line arguments
# leave this in for the moment but we probably will need to update this with input for the dshield config
for arg in "$@"; do
    case $arg in
	"--update" | "--upgrade")
	    if [ -f /etc/dshield.ini ]; then
		echo "Non Interactive Update Mode"
		INTERACTIVE=0
	    else
		echo "Update mode requires a /etc/dshield.ini file"
		exit 9
	    fi
	    ;;
	"--fast")
	    FAST=1
	    echo "Fast mode enabled. This will skip some dependency checks and OS updates"
	    ;;
    esac
done    

# target directory for server components
# these get loaded by the env dockerfile settings but let's check anyway; if they don't exist set them
if [ -z ${TARGETDIR} ]; then
   TARGETDIR="/srv"
   DSHIELDDIR="${TARGETDIR}/dshield"
   COWRIEDIR="${TARGETDIR}/cowrie" # remember to also change the init.d script!
   TXTCMDS=${COWRIEDIR}/share/cowrie/txtcmds
   LOGDIR="${TARGETDIR}/log"
   WEBDIR="${TARGETDIR}/www"
fi
INSTDATE="`date +'%Y-%m-%d_%H%M%S'`"
LOGFILE="${LOGDIR}/install_${INSTDATE}.log"
# setting this as not default
TMPDIR="/tmp"

# which ports will be handled e.g. by cowrie (separated by blanks)
# used e.g. for setting up block rules for trusted nets
# use the ports after PREROUTING has been excecuted, i.e. the redirected (not native) ports
# note: doesn't make sense to ask the user because cowrie is configured statically
#
# <SVC>HONEYPORT: target ports for requests, i.e. where the honey pot daemon listens on
# <SVC>REDIRECT: source ports for requests, i.e. which ports should be redirected to the honey pot daemon
# HONEYPORTS: all ports a honey pot is listening on so that the firewall can be configured accordingly
if [ -z ${SSHHONEYPORT} ]; then
   SSHHONEYPORT=2222
   TELNETHONEYPORT=2223
   WEBHONEYPORT=8000
   SSHREDIRECT="22"
   TELNETREDIRECT="23 2323"
   WEBREDIRECT="80 8080 7547 5555 9000"
   HONEYPORTS="${SSHHONEYPORT} ${TELNETHONEYPORT} ${WEBHONEYPORT}"
fi

# which port the real sshd should listen to >> we don't need this, this will be set by your docker cmd or docker-compose
# SSHDPORT="12222"

# Debug Flag
# 1 = debug logging, debug commands
# 0 = normal logging, no extra commands
DEBUG=1

# REMOVE all dialog aspects, can't do dialogs in build

###########################################################
## FUNCTION SECTION
###########################################################

# echo and log
outlog () {
   echo "${*}"
   do_log "${*}"
}

quotespace() {
    local line="${*}"
    if echo $line | egrep -q ' '; then
	if ! echo $line | egrep -q "'"; then
	    line="'${line}'"
	fi
    fi
    echo "$line"
}

# write log
do_log () {
   if [ ! -d ${LOGDIR} ] ; then
       mkdir -p ${LOGDIR}
       chmod 700 ${LOGDIR}
   fi
   if [ ! -f ${LOGFILE} ] ; then
       touch ${LOGFILE}
       chmod 600 ${LOGFILE}
       outlog "Log ${LOGFILE} started."
       outlog "ATTENTION: the log file contains sensitive information (e.g. passwords, API keys, ...)"
       outlog "           Handle with care. Sanitize before submitting."
   fi
   echo "`date +'%Y-%m-%d_%H%M%S'` ### ${*}" >> ${LOGFILE}
}

# execute and log
# make sure, to be run command is passed within '' or ""
#    if redirects etc. are used
run () {
   do_log "Running: ${*}"
   eval ${*} >> ${LOGFILE} 2>&1
   RET=${?}
   if [ ${RET} -ne 0 ] ; then
      dlog "EXIT CODE NOT ZERO (${RET})!"
   fi
   return ${RET}
}

# run if debug is set
# make sure, to be run command is passed within '' or ""
#    if redirects etc. are used
drun () {
   if [ ${DEBUG} -eq 1 ] ; then
      do_log "DEBUG COMMAND FOLLOWS:"
      do_log "${LINE}"
      run ${*}
      RET=${?}
      do_log "${LINE}"
      return ${RET}
   fi
}

# log if debug is set
dlog () {
   if [ ${DEBUG} -eq 1 ] ; then
      do_log "DEBUG OUTPUT: ${*}"
   fi
}

# copy file(s) and chmod
# $1: file (opt. incl. direcorty / absolute path)
#     can also be a directory, but then chmod can't be done
# $2: dest dir
# optional: $3: chmod bitmask (only if $1 isn't a directory)
do_copy () { 
   dlog "copying ${1} to ${2} and chmod to ${3}"
   if [ -d ${1} ] ; then
      if [ "${3}" != "" ] ; then
         # source is a directory, but chmod bitmask given nevertheless, issue a warning
         dlog "WARNING: do_copy: $1 is a directory, but chmod bitmask given, ignored!"
      fi
      run "cp -r ${1} ${2}"
   else
      run "cp ${1} ${2}"
   fi
   if [ ${?} -ne 0 ] ; then
      outlog "Error copying ${1} to ${2}. Aborting."
      exit 9
   fi
   if [ "${3}" != "" -a ! -d ${1} ] ; then
      # only if $1 isn't a directory!
      if [ -f ${2} ] ; then
         # target is a file, chmod directly
         run "chmod ${3} ${2}"
      else
         # target is a directory, so use basename
         run "chmod ${3} ${2}/`basename ${1}`"
      fi
      if [ ${?} -ne 0 ] ; then
         outlog "Error executing chmod ${3} ${2}/${1}. Aborting."
         exit 9
      fi
   fi

}

###########################################################
## MAIN
###########################################################


###########################################################
## basic checks
###########################################################


echo ${LINE}

userid=`id -u`
if [ ! "$userid" = "0" ]; then
   echo "You have to run this script as root. eg."
   echo "  sudo bin/install.sh"
   echo "Exiting."
   echo ${LINE}
   exit 9
else
   do_log "Check OK: User-ID is ${userid}."
fi

dlog "This is ${0} V${myversion}"

dlog "parent process: $(ps -o comm= $PPID)"

if [ ${DEBUG} -eq 1 ] ; then
   do_log "DEBUG flag is set."
else
   do_log "DEBUG flag NOT set."
fi

drun env
drun 'df -h'
outlog "Checking Pre-Requisits"

dshieldinsdir=$PWD/; # We need this so that we can reference bin/ or docker/ in the scripts
progname=$0;
progdir=`dirname $0`;
progdir=$PWD/$progdir;

dlog "dshield install dir: ${dshieldinsdir}"
dlog "progname: ${progname}"
dlog "progdir: ${progdir}"

cd $progdir

TMPDIR=`mktemp -d -q /tmp/dshieldinstXXXXXXX`
dlog "TMPDIR: ${TMPDIR}"

###########################################################
## OS Install Parts
###########################################################
# DOCKER: we don't care about this, it is set by the dockerfile
# Chopping all OS install related aspects
#
# if [ ! -f /etc/os-release ] ; then
#   outlog "I can not fine the /etc/os-release file. You are likely not running a supported operating systems"
#   outlog "please email info@dshield.org for help."
#   exit 9
# fi
#
# <chop>...
#
# if [ "$ID" == "amzn" ]; then
#    outlog "Updating your Operating System"
#    run 'yum -q update -y'
#    outlog "Installing additional packages"
#    run 'yum -q install -y dialog perl-libwww-perl perl-Switch rng-tools boost-random jq MySQL-python mariadb mariadb-devel iptables-services'
# fi

# if [ ${VALUES} == "manual" ] ; then
#    MANUPDATES=1
# else
#    MANUPDATES=0
# fi

# dlog "MANUPDATES: ${MANUPDATES}"


# clear

# fi
###### End OS Chop..

###########################################################
## Stopping Cowrie if already installed
###########################################################
# DOCKER: we don't care about this, Docker build/run starts neutra

# if [ -x /etc/init.d/cowrie ] ; then
#    outlog "Existing cowrie startup file found, stopping cowrie."
#    run '/etc/init.d/cowrie stop'
#    outlog "... giving cowrie time to stop ..."
#    run 'sleep 10'
#    outlog "... OK."
# fi
# # in case systemd is used
# systemctl stop cowrie

# if [ "$FAST" == "0" ] ; then

###########################################################
## PIP
###########################################################
# DOCKER: we don't care about this, Assume we have the OS based pip installed by the dockerfile
   # outlog "check if pip3 is already installed"

   # run 'pip3 > /dev/null'

   # if [ ${?} -gt 0 ] ; then
   #    outlog "no pip3 found, installing pip3"
   #    run 'wget -qO $TMPDIR/get-pip.py https://bootstrap.pypa.io/get-pip.py'
   #    if [ ${?} -ne 0 ] ; then
   #       outlog "Error downloading get-pip, aborting."
   #       exit 9
   #    fi
   #    run 'python3 $TMPDIR/get-pip.py'
   #    if [ ${?} -ne 0 ] ; then
   #       outlog "Error running get-pip3, aborting."
   #       exit 9
   #    fi   
   # else
   #    # hmmmm ...
   #    # todo: automatic check if pip3 is OS managed or not
   #    # check ... already done :)

   #    outlog "pip3 found .... Checking which pip3 is installed...."

   #    drun 'pip3 -V'
   #    drun 'pip3  -V | cut -d " " -f 4 | cut -d "/" -f 3'
   #    drun 'find /usr -name pip3'
   #    drun 'find /usr -name pip3 | grep -v local'

   #    # if local is in the path then it's normally not a distro package, so if we only find local, then it's OK
   #    # - no local in pip3 -V output 
   #    #   OR
   #    # - pip3 below /usr without local
   #    # -> potential distro pip3 found
   #    if [ `pip3  -V | cut -d " " -f 4 | cut -d "/" -f 3` != "local" -o `find /usr -name pip3 | grep -v local | wc -l` -gt 0 ] ; then
   #       # pip3 may be distro pip3
   #       outlog "Potential distro pip3 found"
   #    else
   #       outlog "pip3 found which doesn't seem to be installed as a distro package. Looks ok to me."
   #    fi

   # fi

# else
#     outlog "Skipping PIP check in FAST mode"
# fi

###########################################################
## Random number generator
###########################################################

#
# yes. this will make the random number generator less secure. but remember this is for a honeypot
#

dlog "Changing random number generator settings."
run 'echo "HRNGDEVICE=/dev/urandom" > /etc/default/rnd-tools'


###########################################################
## DOCKER: FROM THIS POINT WE DEVIATE FROM ORIGINAL INSTALLER SCRIPT
## many of the OS configuration aspects are not required
## all interactive components are remove as cannot work
###########################################################

###########################################################
## Disable IPv6
###########################################################
# DOCKER: we don't care about this, IPv6 needs to be enabled in docker and set-up assume, that the docker user knows what he is doing

# dlog "Disabling IPv6 in /etc/modprobe.d/ipv6.conf"
# run "mv /etc/modprobe.d/ipv6.conf /etc/modprobe.d/ipv6.conf.bak"
# cat > /etc/modprobe.d/ipv6.conf <<EOF
# # Don't load ipv6 by default
# alias net-pf-10 off
# # uncommented
# alias ipv6 off
# # added
# options ipv6 disable_ipv6=1
# # this is needed for not loading ipv6 driver
# blacklist ipv6
# EOF
# run "chmod 644 /etc/modprobe.d/ipv6.conf"
# drun "cat /etc/modprobe.d/ipv6.conf.bak"
# drun "cat /etc/modprobe.d/ipv6.conf"


###########################################################
## Handling existing config
###########################################################

if [ -f /etc/dshield.ini ] ; then
   dlog "dshield.ini found, content follows"
   drun 'cat /etc/dshield.ini'
   dlog "securing dshield.ini"
   run 'chmod 600 /etc/dshield.ini'
   run 'chown root:root /etc/dshield.ini'
   outlog "reading old configuration"
   if grep -q 'uid=<authkey>' /etc/dshield.ini; then
      dlog "erasing <.*> pattern from dshield.ini"
      run "sed -i.bak 's/<.*>//' /etc/dshield.ini"
      dlog "modified content of dshield.ini follows"
      drun 'cat /etc/dshield.ini'
   fi
   # believe it or not, bash has a built in .ini parser. Just need to remove spaces around "="
   source <(grep = /etc/dshield.ini | sed 's/ *= */=/g')
   dlog "dshield.ini found, content follows"
   drun 'cat /etc/dshield.ini'
   dlog "securing dshield.ini"
   run 'chmod 600 /etc/dshield.ini'
   run 'chown root:root /etc/dshield.ini'

   # Moved the check userid into the existing dshield.ini file
   uid=$userid
   echo "check $userid $apikey"
   if [ "$userid" == "" ]; then
	   echo "Docker run mode, dshield.ini has to contain a userid."
	   exit 9
   fi
fi

if [ "$email" == "" ]; then
   echo "Docker run mode, dshield.ini or arguments has to contain an email."
   exit 9
fi

if [ "$apikey" == "" ]; then
   echo "Docker run mode, dshield.ini or arguments has to contain an apikey."
   exit 9
fi

###########################################################
## DShield Account
###########################################################
#
# DOCKER:
# DShield account information will need to be passed via command line or docker-secrets
#

# Let's check the dshield account information is valid
dlog "Got email ${email} and apikey ${apikey}"
dlog "Calculating nonce."
nonce=`openssl rand -hex 10`
dlog "Calculating hash."
hash=`echo -n $email:$apikey | openssl dgst -hmac $nonce -sha512 -hex | cut -f2 -d'=' | tr -d ' '`
dlog "Calculated nonce (${nonce}) and hash (${hash})."

# TODO: urlencode($user)
user=`echo $email | sed 's/+/%2b/' | sed 's/@/%40/'`
dlog "Checking API key ..."
run 'curl -s https://isc.sans.edu/api/checkapikey/$user/$nonce/$hash/$myversion > $TMPDIR/checkapi'

dlog "Curl return code is ${?}"

if ! [ -d "$TMPDIR" ]; then
   # this SHOULD NOT happpen
   outlog "Can not find TMPDIR ${TMPDIR}"
   exit 9
fi

drun "cat ${TMPDIR}/checkapi"

dlog "Examining result of API key check ..."

if grep -q '<result>ok</result>' $TMPDIR/checkapi ; then
   apikeyok=1;
   uid=`grep  '<id>.*<\/id>' $TMPDIR/checkapi | sed -E 's/.*<id>([0-9]+)<\/id>.*/\1/'`
   dlog "API key OK, uid is ${uid}"
else
   dlog "API key not OK, informing user"
   exit 5
fi

###########################################################
## Firewall Configuration
###########################################################
#
# DOCKER:
# All network port stuff is carried out by either yoru docker run command or docker-compose, etc
# we don't have a firewall on a docker for the simple reason that all network activity is managed by the docker engine
#
# TO DO Docker: look at how we can maybe pull the firewall data from the hose machine
#
##---------------------------------------------------------
## default interface 
##---------------------------------------------------------
#
# DOCKER: the container interface is the default. We will assume the image runs only in one network at all times

dlog "docker config: figuring out default interface"

# if we don't have one configured, try to figure it out
dlog "interface: ${interface}"
drun 'ip link show'
if [ "$interface" == "" ] ; then
   dlog "Trying to figure out interface"
   # we don't expect a honeypot connected by WLAN ... but the user can change this of course
   drun "ip -4 route show| grep '^default ' | cut -f5 -d' '"
   interface=`ip -4 route show| grep '^default ' | cut -f5 -d' '`
fi

# list of valid interfaces
drun "ip link show | grep '^[0-9]' | cut -f2 -d':' | tr -d '\n' | sed 's/^ //'"
validifs=`ip link show | grep '^[0-9]' | cut -f2 -d':' | tr -d '\n' | sed 's/^ //'`

# get honeypot external IPv4 address
honeypotip=$(curl -s https://www4.dshield.org/api/myip?json  | jq .ip | tr -d '"')

dlog "validifs: ${validifs}"

# In Docker the default interface will always be the one we use for the honeypot
dlog "Interface: $interface"

##---------------------------------------------------------
## figuring out local network
##---------------------------------------------------------
# DOCKER: Leaving this here to get default values when building

dlog "firewall config: figuring out local network"

drun "ip addr show $interface"
drun "ip addr show $interface | grep 'inet ' |  awk '{print \$2}' | cut -f1 -d'/'"
ipaddr=`ip addr show $interface | grep 'inet ' |  awk '{print $2}' | cut -f1 -d'/'`
dlog "ipaddr: ${ipaddr}"

drun "ip route show"
drun "ip route show | grep $interface | grep 'scope link' | grep '/' | cut -f1 -d' '"
localnet=`ip route show | grep $interface | grep 'scope link' | cut -f1 -d' '`
# added most common private subnets. This will help if the Pi is in its
# own subnet (e.g. 192.168.1.0/24) which is part of a larger network.
# either way, hits from private IPs are hardly ever log worthy.
if echo $localnet | grep -q '^10\.'; then localnet='10.0.0.0/8'; fi
if echo $localnet | grep -q '^192\.168\.'; then localnet='192.168.0.0/16'; fi
if echo $localnet | grep -q '^172\.1[6-9]\.'; then localnet='172.16.0.0/12'; fi
if echo $localnet | grep -q '^172\.2[0-9]\.'; then localnet='172.16.0.0/12'; fi
if echo $localnet | grep -q '^172\.3[0-1]\.'; then localnet='172.16.0.0/12'; fi
dlog "localnet: ${localnet}"

# additionally we will use any connection to current sshd 
# DOCKER: DURING BUILD NOTHING IS CONNECTED SO THIS IS OUT OF SCOPE
CONIPS="$localips ${CONIPS}"
dlog "CONIPS with config values before removing duplicates: ${CONIPS}"
CONIPS=`echo ${CONIPS} | tr ' ' '\n' | egrep '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u | tr '\n' ' ' | sed 's/ $//'`
dlog "CONIPS with removed duplicates: ${CONIPS}"

localips="'${CONIPS}'"
adminports="'${ADMINPORTS}'"


##---------------------------------------------------------
## IPs for which logging should be disabled
##---------------------------------------------------------
# DOCKER we can skip this no firewall on the container

##---------------------------------------------------------
## disable honeypot for nets / IPs
##---------------------------------------------------------

dlog "firewall config: IPs and ports to disable honeypot for"

if [ "${nohoneyips}" == "" ] ; then
   # default: admin IPs and nets
   nohoneyips="${NOFWLOGGING}"
fi
dlog "nohoneyips: ${nohoneyips}"

if [ "${nohoneyports}" == "" ] ; then
   # default: cowrie ports
   nohoneyports="${HONEYPORTS}"
fi
dlog "nohoneyports: ${nohoneyports}"


# for saving in dshield.conf
nohoneyips="'${NOHONEYIPS}'"
nohoneyports="'${NOHONEYPORTS}'"

dlog "final values: "
dlog "NOHONEYIPS: ${NOHONEYIPS} / NOHONEYPORTS: ${NOHONEYPORTS}"
dlog "nohoneyips: ${nohoneyips} / nohoneyports: ${nohoneyports}"

##---------------------------------------------------------
## create actual firewall rule set
##---------------------------------------------------------
#
# DOCKER: NO Firewall in container....
#         Redirection happens in the docker run command
#


###########################################################
## Change real SSHD port
###########################################################
# DOCKER: no SSH deamon, connect via an docker exec command


###########################################################
## Modifying syslog config
###########################################################
dlog "setting interface in syslog config"
# no %%interface%% in dshield.conf template anymore, so only copying file
# run 'sed "s/%%interface%%/$interface/" < $progdir/../etc/rsyslog.d/dshield.conf > /etc/rsyslog.d/dshield.conf'
do_copy $progdir/../etc/rsyslog.d/dshield.conf /etc/rsyslog.d 600

drun 'cat /etc/rsyslog.d/dshield.conf'

###########################################################
## Further copying / configuration
###########################################################


#
# moving dshield stuff to target directory
# (don't like to have root run scripty which are not owned by root)
#

run "mkdir -p ${DSHIELDDIR}"
do_copy $progdir/../srv/dshield/fwlogparser.py ${DSHIELDDIR} 700
do_copy $progdir/../srv/dshield/weblogsubmit.py ${DSHIELDDIR} 700
do_copy $progdir/../srv/dshield/DShield.py ${DSHIELDDIR} 700

# check: automatic updates allowed?
# set this in the entrypoint script so it is valid for each image run
# if [ "$MANUPDATES" -eq  "0" ]; then
#    dlog "automatic updates OK, configuring"
#    run 'touch ${DSHIELDDIR}/auto-update-ok'
# fi


#
# "random" offset for cron job so not everybody is reporting at once
#

dlog "creating /etc/cron.d/dshield"
offset1=`shuf -i0-29 -n1`
offset2=$((offset1+30));
echo "${offset1},${offset2} * * * * root cd ${DSHIELDDIR}; ./weblogsubmit.py" > /etc/cron.d/dshield 
echo "${offset1},${offset2} * * * * root ${DSHIELDDIR}/fwlogparser.py" >> /etc/cron.d/dshield
offset1=`shuf -i0-59 -n1`
offset2=`shuf -i0-23 -n1`
echo "${offset1} ${offset2} * * * root cd ${progdir}; ./update.sh --cron >/dev/null " >> /etc/cron.d/dshield
offset1=`shuf -i0-59 -n1`
offset2=`shuf -i0-23 -n1`
echo "${offset1} ${offset2} * * * root /sbin/reboot" >> /etc/cron.d/dshield


drun 'cat /etc/cron.d/dshield'


#
# Update dshield Configuration
#
dlog "creating new /etc/dshield.ini"
if [ -f /etc/dshield.ini ]; then
   dlog "old dshield.ini follows"
   drun 'cat /etc/dshield.ini'
   run 'mv /etc/dshield.ini /etc/dshield.ini.${INSTDATE}'
fi

# new shiny config file
run 'touch /etc/dshield.ini'
run 'chmod 600 /etc/dshield.ini'
run 'echo "[DShield]" >> /etc/dshield.ini'
run 'echo "interface=$interface" >> /etc/dshield.ini'
run 'echo "version=$myversion" >> /etc/dshield.ini'
run 'echo "email=$email" >> /etc/dshield.ini'
run 'echo "userid=$uid" >> /etc/dshield.ini'
run 'echo "apikey=$apikey" >> /etc/dshield.ini'
run 'echo "# the following lines will be used by a new feature of the submit code: "  >> /etc/dshield.ini'
run 'echo "# replace IP with other value and / or anonymize parts of the IP"  >> /etc/dshield.ini'
run 'echo "honeypotip=$honeypotip" >> /etc/dshield.ini'
run 'echo "replacehoneypotip=" >> /etc/dshield.ini'
run 'echo "anonymizeip=" >> /etc/dshield.ini'
run 'echo "anonymizemask=" >> /etc/dshield.ini'
run 'echo "fwlogfile=/var/log/dshield.log" >> /etc/dshield.ini'
nofwlogging=$(quotespace $nofwlogging)
run 'echo "nofwlogging=$nofwlogging" >> //etc/dshield.ini'
CONIPS="$(quotespace $CONIPS)"
run 'echo "localips=$CONIPS" >> /etc/dshield.ini'
ADMINPORTS=$(quotespace $ADMINPORTS)
run 'echo "adminports=$ADMINPORTS" >> /etc/dshield.ini'
nohoneyips=$(quotespace $nohoneyips)
run 'echo "nohoneyips=$nohoneyips" >> /etc/dshield.ini'
nohoneyports=$(quotespace $nohoneyports)
run 'echo "nohoneyports=$nohoneyports" >> /etc/dshield.ini'
run 'echo "logretention=7" >> /etc/dshield.ini'
run 'echo "minimumcowriesize=1000" >> /etc/dshield.ini'
run 'echo "manualupdates=$MANUPDATES" >> /etc/dshield.ini'
dlog "new /etc/dshield.ini follows"
drun 'cat /etc/dshield.ini'


###########################################################
## Installation of cowrie
###########################################################


#
# installing cowrie
# TODO: don't use a static path but a configurable one
#
# 2017-05-17: revised section to reflect current installation instructions
#             https://github.com/micheloosterhof/cowrie/blob/master/INSTALL.md
#

dlog "installing cowrie"

# step 1 (Install OS dependencies): done
 
# step 2 (Create a user account)
dlog "checking if cowrie OS user already exists"
if ! grep '^cowrie:' -q /etc/passwd; then
   dlog "... no, creating"
   run "adduser --gecos 'Honeypot,A113,555-1212,555-1212' --disabled-password --quiet --home ${COWRIEDIR} --no-create-home cowrie"
   outlog "Added user 'cowrie'"
else
   outlog "User 'cowrie' already exists in OS. Making no changes to OS user."
fi

# step 3 (Checkout the code)
# (we will stay with zip instead of using GIT for the time being)
dlog "downloading and unzipping cowrie"
#run "wget -qO $TMPDIR/cowrie.zip https://www.dshield.org/cowrie.zip"
run "curl -Ls -o $TMPDIR/cowrie.zip https://www.dshield.org/cowrie.zip"


if [ ${?} -ne 0 ] ; then
   outlog "Something went wrong downloading cowrie, ZIP corrupt."
   exit 9
fi
if [ -f $TMPDIR/cowrie.zip ]; then
  run "unzip -qq -d $TMPDIR $TMPDIR/cowrie.zip "
else 
  outlog "Can not find cowrie.zip in $TMPDIR"
  exit 9
fi
if [ -d ${COWRIEDIR} ]; then
   dlog "old cowrie installation found, moving"
   run "mv ${COWRIEDIR} ${COWRIEDIR}.${INSTDATE}"
fi
dlog "moving extracted cowrie to ${COWRIEDIR}"
if [ -d $TMPDIR/cowrie-master ]; then
 run "mv $TMPDIR/cowrie-master ${COWRIEDIR}"
else
 outlog "$TMPDIR/cowrie not found"
 exit 9
fi

# step 4 (Setup Virtual Environment)
outlog "Installing Python packages with PIP. This will take a LOOONG time."
OLDDIR=`pwd`
cd ${COWRIEDIR}
dlog "setting up virtual environment"
run 'virtualenv cowrie-env'
dlog "activating virtual environment"
run 'source cowrie-env/bin/activate'
dlog "installing dependencies: requirements.txt"
run 'pip3 install --upgrade pip3'
run 'pip3 install --upgrade -r requirements.txt'
run 'pip3 install --upgrade -r requirements-output.txt'
run 'pip3 install --upgrade bcrypt'
run 'pip3 install --upgrade pip3'
run 'pip3 install --upgrade -r requirements.txt'
run 'pip3 install --upgrade -r requirements-output.txt'
run 'pip3 install --upgrade bcrypt'
run 'pip3 install --upgrade requests'
if [ ${?} -ne 0 ] ; then
   outlog "Error installing dependencies from requirements.txt. See ${LOGFILE} for details.

   This part often fails due to timeouts from the servers hosting python packages. Best to try to rerun the install script again. It should remember your settings.
"
   exit 9
fi

# installing python dependencies. Most of these are for cowrie.
run 'pip3 install -r requirements.txt'
cd ${OLDDIR}


### This section moved to entrypoint to create per instance values
outlog "Entrypoint for docker does further cowrie configuration."

# # step 6 (Generate a DSA key)
# dlog "generating cowrie SSH hostkey"
# run "ssh-keygen -t dsa -b 1024 -N '' -f ${COWRIEDIR}/var/lib/cowrie/ssh_host_dsa_key "

# # step 5 (Install configuration file)
# dlog "copying cowrie.cfg and adding entries"
# # adjust cowrie.cfg
# export uid
# export apikey
# export hostname=`shuf /usr/share/dict/american-english | head -1 | sed 's/[^a-z]//g'`
# export sensor_name=dshield-$uid-$version
# fake1=`shuf -i 1-255 -n 1`
# fake2=`shuf -i 1-255 -n 1`
# fake3=`shuf -i 1-255 -n 1`
# export fake_addr=`printf "10.%d.%d.%d" $fake1 $fake2 $fake3`
# export arch=`arch`
# export kernel_version=`uname -r`
# export kernel_build_string=`uname -v | sed 's/SMP.*/SMP/'`
# export ssh_version=`ssh -V 2>&1 | cut -f1 -d','`
# export ttylog='false'
# drun "cat ..${COWRIEDIR}/cowrie.cfg | envsubst > ${COWRIEDIR}/cowrie.cfg"

# # make output of simple text commands more real

# dlog "creating output for text commands"

# run "mkdir -p ${TXTCMDS}/bin"
# run "mkdir -p ${TXTCMDS}/usr/bin"
# run "df > ${TXTCMDS}/bin/df"
# run "dmesg > ${TXTCMDS}/bin/dmesg"
# run "mount > ${TXTCMDS}/bin/mount"
# run "ulimit > ${TXTCMDS}/bin/ulimit"
# run "lscpu > ${TXTCMDS}/usr/bin/lscpu"
# run "echo '-bash: emacs: command not found' > ${TXTCMDS}/usr/bin/emacs"
# run "echo '-bash: locate: command not found' > ${TXTCMDS}/usr/bin/locate"

run 'chown -R cowrie:cowrie ${COWRIEDIR}'

# echo "###########  $progdir  ###########"

dlog "copying cowrie system files"

do_copy $progdir/../lib/systemd/system/cowrie.service /lib/systemd/system/cowrie.service 644
do_copy $progdir/../etc/cron.hourly/cowrie /etc/cron.hourly 755

# make sure to remove old cowrie start if they exist
if [ -f /etc/init.d/cowrie ] ; then
    rm -f /etc/init.d/cowrie
fi
run 'mkdir ${COWRIEDIR}/log'
run 'chmod 755 ${COWRIEDIR}/log'
run 'chown cowrie:cowrie ${COWRIEDIR}/log'
run 'mkdir ${COWRIEDIR}/log/tty'
run 'chmod 755 ${COWRIEDIR}/log/tty'
run 'chown cowrie:cowrie ${COWRIEDIR}/log/tty'
find /etc/rc?.d -name '*cowrie*' -delete
run 'systemctl daemon-reload'
run 'systemctl enable cowrie.service'


###########################################################
## Installation of web honeypot
###########################################################

dlog "installing web honeypot"

if [ -d ${WEBDIR} ]; then
   dlog "old web honeypot installation found, moving"
   # TODO: warn user, backup dl etc.
   run "mv ${WEBDIR} ${WEBDIR}.${INSTDATE}"
fi

run "mkdir -p ${WEBDIR}"

do_copy $progdir/../srv/www ${WEBDIR}/../
do_copy $progdir/../lib/systemd/system/webpy.service /lib/systemd/system/ 644
run "systemctl enable webpy.service"
#run "systemctl enable systemd-networkd.service systemd-networkd-wait-online.service"
run "systemctl daemon-reload"

# change ownership for web databases to cowrie as we will run the
# web honeypot as cowrie
touch ${WEBDIR}/DB/webserver.sqlite
run "chown cowrie ${WEBDIR}/DB"
run "chown cowrie ${WEBDIR}/DB/*"


###########################################################
## Copying further system files
###########################################################

dlog "copying further system files"
# no longer needed. now done bu /etc/cron.d/dshield
# do_copy $progdir/../etc/cron.hourly/dshield /etc/cron.hourly 755
if [ -f /etc/cron.hourly/dshield ]; then
    run "rm /etc/cron.hourly/dshield"
fi
# do_copy $progdir/../etc/mini-httpd.conf /etc/mini-httpd.conf 644
# do_copy $progdir/../etc/default/mini-httpd /etc/default/mini-httpd 644


###########################################################
## Remove old mini-httpd stuff (if run as an update)
###########################################################
## This is moved to the entrypoint script which would be main update part, any new build would generate a new env.

# dlog "removing old mini-httpd stuff"
# if [ -f /etc/mini-httpd.conf ] ; then
#    mv /etc/mini-httpd.conf /etc/mini-httpd.conf.${INSTDATE}
# fi
# if [ -f /etc/default/mini-httpd ] ; then
#    run 'update-rc.d mini-httpd disable'
#    run 'update-rc.d -f mini-httpd remove'
#    mv /etc/default/mini-httpd /etc/default/.mini-httpd.${INSTDATE}
# fi



###########################################################
## Setting up Services
###########################################################


# setting up services
dlog "setting up services: cowrie"
run 'update-rc.d cowrie defaults'
# run 'update-rc.d mini-httpd defaults'


###########################################################
## Setting up postfix
###########################################################
# For docker we leave the postfix install here because of required configuration

   outlog "Installing and configuring postfix."
   # dlog "uninstalling postfix"
   # run 'apt -y -q purge postfix'
    dlog "preparing installation of postfix"
    echo "postfix postfix/mailname string docker" | debconf-set-selections
    echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
    echo "postfix postfix/mynetwork string '127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128'" | debconf-set-selections
    echo "postfix postfix/destinations string docker, localhost.localdomain, localhost" | debconf-set-selections
    outlog "package configuration for postfix"
    run 'debconf-get-selections | grep postfix'
   #  dlog "installing postfix"
   #  run 'apt -y -q install postfix'

if grep -q 'inet_protocols = all' /etc/postfix/main.cf ; then
    sed -i 's/inet_protocols = all/inet_protocols = ipv4/' /etc/postfix/main.cf
fi

###########################################################
## Configuring MOTD
###########################################################

#
# modifying motd
#

dlog "installing /etc/motd"
cat > $TMPDIR/motd <<EOF

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

***
***    DShield Honeypot
***

EOF

run "mv $TMPDIR/motd /etc/motd"
run "chmod 644 /etc/motd"
run "chown root:root /etc/motd"

drun "cat /etc/motd"


###########################################################
## Handling of CERTs
###########################################################
## Moving this to entry point so that certs are generated per run.. hostname changes each time


#
# creating PID directory
#

run 'mkdir /var/run/dshield'

# rotate dshield firewall logs
do_copy $progdir/../etc/logrotate.d/dshield /etc/logrotate.d 644
if [ -f "/etc/cron.daily/logrotate" ]; then
  run "mv /etc/cron.daily/logrotate /etc/cron.hourly"
fi 

###########################################################
## Done :)
###########################################################

outlog
outlog
outlog Done. 
outlog
# outlog "Please reboot your Pi now."
# outlog
outlog "For feedback, please e-mail jullrich@sans.edu or file a bug report on github"
outlog "Please include a sanitized version of /etc/dshield.ini in bug reports"
outlog "as well as a very carefully sanitized version of the installation log "
outlog "  (${LOGFILE})."
outlog
outlog "IMPORTANT:  connect using docker exec command to /bin/bash"
outlog
outlog "### Thank you for supporting the ISC and dshield! ###"
outlog
outlog "To check if all is working right:"
outlog "   Run the script 'status.sh' "
outlog "   or check https://isc.sans.edu/myreports.sh (after logging in)"
outlog
outlog " for help, check our slack channel: https://isc.sans.edu/slack "



