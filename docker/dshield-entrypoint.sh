#!/bin/bash
####
#
#  Docker entrypoint Script for the container version of dshield
#  The script finalise the configuration (per instance run) and starts the services
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

readonly myversion=75

#
# Major Changes (for details see Github):
#
# - V75 (Fvt)
#   - Changes to support a full Dockerfile and docker container deployment
#   - This is the docker entry point script
#


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

progname=$0;
progdir=`dirname $0`;
progdir=$PWD/$progdir;

dlog "progname: ${progname}"
dlog "progdir: ${progdir}"

cd $progdir


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

# check: automatic updates allowed?

if [ "$MANUPDATES" -eq  "0" ]; then
   dlog "automatic updates OK, configuring"
   run 'touch ${DSHIELDDIR}/auto-update-ok'
fi

#
# Update dshield Configuration
#
dlog "creating new /etc/dshield.ini"
if [ -f /etc/dshield.ini ]; then
   dlog "old dshield.ini follows"
   drun 'cat /etc/dshield.ini'
   run 'mv /etc/dshield.ini /etc/dshield.ini.${INSTDATE}'
fi

# new shiny config file LIN 761
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
## Finalisation of cowrie set-up
###########################################################

outlog "Doing further cowrie configuration."

# step 6 (Generate a DSA key)
dlog "generating cowrie SSH hostkey"
run "ssh-keygen -t dsa -b 1024 -N '' -f ${COWRIEDIR}/var/lib/cowrie/ssh_host_dsa_key "

# step 5 (Install configuration file)
dlog "copying cowrie.cfg and adding entries"
# adjust cowrie.cfg
export uid
export apikey
export hostname=`shuf /usr/share/dict/american-english | head -1 | sed 's/[^a-z]//g'`
export sensor_name=dshield-$uid-$version
fake1=`shuf -i 1-255 -n 1`
fake2=`shuf -i 1-255 -n 1`
fake3=`shuf -i 1-255 -n 1`
export fake_addr=`printf "10.%d.%d.%d" $fake1 $fake2 $fake3`
export arch=`arch`
export kernel_version=`uname -r`
export kernel_build_string=`uname -v | sed 's/SMP.*/SMP/'`
export ssh_version=`ssh -V 2>&1 | cut -f1 -d','`
export ttylog='false'
drun "cat ..${COWRIEDIR}/cowrie.cfg | envsubst > ${COWRIEDIR}/cowrie.cfg"

# make output of simple text commands more real

dlog "creating output for text commands"

run "mkdir -p ${TXTCMDS}/bin"
run "mkdir -p ${TXTCMDS}/usr/bin"
run "df > ${TXTCMDS}/bin/df"
run "dmesg > ${TXTCMDS}/bin/dmesg"
run "mount > ${TXTCMDS}/bin/mount"
run "ulimit > ${TXTCMDS}/bin/ulimit"
run "lscpu > ${TXTCMDS}/usr/bin/lscpu"
run "echo '-bash: emacs: command not found' > ${TXTCMDS}/usr/bin/emacs"
run "echo '-bash: locate: command not found' > ${TXTCMDS}/usr/bin/locate"

run 'chown -R cowrie:cowrie ${COWRIEDIR}'

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
run "systemctl enable systemd-networkd.service systemd-networkd-wait-online.service"
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

dlog "removing old mini-httpd stuff"
if [ -f /etc/mini-httpd.conf ] ; then
   mv /etc/mini-httpd.conf /etc/mini-httpd.conf.${INSTDATE}
fi
if [ -f /etc/default/mini-httpd ] ; then
   run 'update-rc.d mini-httpd disable'
   run 'update-rc.d -f mini-httpd remove'
   mv /etc/default/mini-httpd /etc/default/.mini-httpd.${INSTDATE}
fi

###########################################################
## Handling of CERTs
###########################################################
#
# checking / generating certs
# if already there: ask if generate new
#

dlog "checking / generating certs"

GENCERT=1
if [ ! -f ../etc/CA/ca.serial ]; then
    echo 01 > ../etc/CA/ca.serial
fi
drun "ls ../etc/CA/certs/*.crt 2>/dev/null"
if [ `ls ../etc/CA/certs/*.crt 2>/dev/null | wc -l ` -gt 0 ]; then
   # If we have existing certs clean them
   # cleaning up old certs
   run 'rm ../etc/CA/certs/*'
   run 'rm ../etc/CA/keys/*'
   run 'rm ../etc/CA/requests/*'
   run 'rm ../etc/CA/index.*'
   GENCERT=1
 fi

if [ ${GENCERT} -eq 1 ] ; then
   dlog "generating new CERTs using ./makecert.sh"
   ./makecert.sh
fi

###########################################################
## Need to make sure all the daemons are running now
###########################################################
run "systemctl enable webpy.service"
run "systemctl enable systemd-networkd.service systemd-networkd-wait-online.service"
run 'systemctl enable cowrie.service'
run 'systemctl daemon-reload'

###########################################################
## Done :)
###########################################################

outlog
outlog
outlog Done. 
outlog
outlog "dshield docker instance running."
outlog
outlog "For feedback, please e-mail jullrich@sans.edu or file a bug report on github"
outlog "Please include a sanitized version of /etc/dshield.ini in bug reports"
outlog "as well as a very carefully sanitized version of the installation log "
outlog "  (${LOGFILE})."
outlog
outlog "IMPORTANT: after rebooting, the Pi's ssh server will listen on port ${SSHDPORT}"
outlog "           connect using ssh -p ${SSHDPORT} $SUDO_USER@$ipaddr"
outlog
outlog "### Thank you for supporting the ISC and dshield! ###"
outlog
outlog "To check if all is working right:"
outlog "   Run the script 'status.sh' "
outlog "   or check https://isc.sans.edu/myreports.sh (after logging in)"
outlog
outlog " for help, check our slack channel: https://isc.sans.edu/slack "



