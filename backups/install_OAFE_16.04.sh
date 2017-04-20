#!/bin/bash -
#===============================================================================
# vim: softtabstop=4 shiftwidth=4 expandtab fenc=utf-8 spell spelllang=en cc=81
#===============================================================================
start=$(date +%s.%N)

#--- FUNCTION ----------------------------------------------------------------
# NAME: __function_defined
# DESCRIPTION: Checks if a function is defined within this scripts scope
# PARAMETERS: function name
# RETURNS: 0 or 1 as in defined or not defined
#-------------------------------------------------------------------------------
__function_defined() {
    FUNC_NAME=$1http://download.virtualbox.org/virtualbox/debian/dists/xenial/contrib/
    if [ "$(command -v $FUNC_NAME)x" != "x" ]; then
        echoinfo "Found function $FUNC_NAME"
        return 0
    fi

    echodebug "$FUNC_NAME not found...."
    return 1
}

#--- FUNCTION ----------------------------------------------------------------
# NAME: __strip_duplicates
# DESCRIPTION: Strip duplicate strings
#-------------------------------------------------------------------------------
__strip_duplicates() {
    echo $@ | tr -s '[:space:]' '\n' | awk '!x[$0]++'
}

#--- FUNCTION ----------------------------------------------------------------
# NAME: echoerr
# DESCRIPTION: Echo errors to stderr.
#-------------------------------------------------------------------------------
echoerror() {
    printf "${RC} * ERROR${EC}: $@\n" 1>&2;
}

#--- FUNCTION ----------------------------------------------------------------
# NAME: echoinfo
# DESCRIPTION: Echo information to stdout.
#-------------------------------------------------------------------------------
echoinfo() {
    printf "${GC} * INFO${EC}: %s\n" "$@";
}

#--- FUNCTION ----------------------------------------------------------------
# NAME: echowarn
# DESCRIPTION: Echo warning informations to stdout.
#-------------------------------------------------------------------------------
echowarn() {
    printf "${YC} * WARN${EC}: %s\n" "$@";
}

#--- FUNCTION ----------------------------------------------------------------
# NAME: echodebug
# DESCRIPTION: Echo debug information to stdout.
#-------------------------------------------------------------------------------
echodebug() {
    if [ $_ECHO_DEBUG -eq $BS_TRUE ]; then
        printf "${BC} * DEBUG${EC}: %s\n" "$@";
    fi
}

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  __apt_get_install_noinput
#   DESCRIPTION:  (DRY) apt-get install with noinput options
#-------------------------------------------------------------------------------
__apt_get_install_noinput() {
    apt-get install -y -o DPkg::Options::=--force-confold $@; return $?
}

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  __apt_get_upgrade_noinput
#   DESCRIPTION:  (DRY) apt-get upgrade with noinput options
#-------------------------------------------------------------------------------
__apt_get_upgrade_noinput() {
    apt-get upgrade -y -o DPkg::Options::=--force-confold $@; return $?
}

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  __pip_install_noinput
#   DESCRIPTION:  (DRY)
#-------------------------------------------------------------------------------
__pip_install_noinput() {
    pip install --upgrade $@; return $?
}

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  __pip_install_noinput
#   DESCRIPTION:  (DRY)
#-------------------------------------------------------------------------------
__pip_pre_install_noinput() {
    pip install --pre --upgrade $@; return $?
}

__check_apt_lock() {
    lsof /var/lib/dpkg/lock > /dev/null 2>&1
    RES=`echo $?`
    return $RES
}


__enable_universe_repository() {
    if [ "x$(grep -R universe /etc/apt/sources.list /etc/apt/sources.list.d/ | grep -v '#')" != "x" ]; then
        # The universe repository is already enabled
        return 0
    fi

    echodebug "Enabling the universe repository"

    # Ubuntu versions higher than 12.04 do not live in the old repositories
    if [ $DISTRO_MAJOR_VERSION -gt 12 ] || ([ $DISTRO_MAJOR_VERSION -eq 12 ] && [ $DISTRO_MINOR_VERSION -gt 04 ]); then
        add-apt-repository -y "deb http://archive.ubuntu.com/ubuntu $(lsb_release -sc) universe" || return 1
    elif [ $DISTRO_MAJOR_VERSION -lt 11 ] && [ $DISTRO_MINOR_VERSION -lt 10 ]; then
        # Below Ubuntu 11.10, the -y flag to add-apt-repository is not supported
        add-apt-repository "deb http://old-releases.ubuntu.com/ubuntu $(lsb_release -sc) universe" || return 1
    fi

    add-apt-repository -y "deb http://old-releases.ubuntu.com/ubuntu $(lsb_release -sc) universe" || return 1

    return 0
}

__enable_docker_repository() {
  apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
  add-apt-repository -y "deb https://apt.dockerproject.org/repo ubuntu-$(lsb_release -sc) main"
}

__check_unparsed_options() {
    shellopts="$1"
    # grep alternative for SunOS
    if [ -f /usr/xpg4/bin/grep ]; then
        grep='/usr/xpg4/bin/grep'
    else
        grep='grep'
    fi
    unparsed_options=$( echo "$shellopts" | ${grep} -E '(^|[[:space:]])[-]+[[:alnum:]]' )
    if [ "x$unparsed_options" != "x" ]; then
        usage
        echo
        echoerror "options are only allowed before install arguments"
        echo
        exit 1
    fi
}

configure_cpan() {
    (echo y;echo o conf prerequisites_policy follow;echo o conf commit)|cpan > /dev/null
}

usage() {
    echo "usage"
    exit 1
}

remove_bad_old_deps() {
    echoinfo "Removing old, conflicting, or bad packages ..."
    apt-get remove -y binplist >> $HOME/oafe-install.log 2>&1 || return 1
    apt-get remove -y unity-webapps-common  >> $HOME/oafe-install.log 2>&1 || return 1
}

install_ubuntu_16.04_deps() {
    echoinfo "Updating your APT Repositories ... "
    apt-get update >> $HOME/oafe-install.log 2>&1 || return 1

    echoinfo "Installing MySQL Server"
    debconf-set-selections <<< 'mysql-server mysql-server/root_password password changeme!' >> $HOME/oafe-install.log 2>&1  || return 1
    debconf-set-selections <<< 'mysql-server mysql-server/root_password_again password changeme!' >> $HOME/oafe-install.log 2>&1  || return 1
    apt-get update >> $HOME/oafe-install.log 2>&1  || return 1
    apt-get install -y mysql-server >> $HOME/oafe-install.log 2>&1  || return 1

    echoinfo "Installing Python Software Properies ... "
    __apt_get_install_noinput software-properties-common >> $HOME/oafe-install.log 2>&1  || return 1

    echoinfo "Enabling Universal Repository ... "
    __enable_universe_repository >> $HOME/oafe-install.log 2>&1 || return 1

    echoinfo "Enabling Docker Repository ... "
    __enable_docker_repository >> $HOME/oafe-install.log 2>&1 || return 1

#    echoinfo "Adding Ubuntu Tweak Repository"
#    add-apt-repository -y ppa:tualatrix/ppa  >> $HOME/oafe-install.log 2>&1 || return 1

    echoinfo "Adding SIFT Repository: dev"
    add-apt-repository -y ppa:sift/dev  >> $HOME/oafe-install.log 2>&1 || return 1

    echoinfo "Adding GIFT Ropository: Stable"
    add-apt-repository -y ppa:gift/dev >> $HOME/oafe-install.log 2>&1 || return 1

    echoinfo "Adding Oracle VirtualBox Repository"
    echo deb http://download.virtualbox.org/virtualbox/debian xenial contrib | tee /etc/apt/sources.list.d/virtualbox.list >> $HOME/oafe-install.log 2>&1 || return 1
    wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add - >> $HOME/oafe-install.log 2>&1 || return 1
    wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | sudo apt-key add ->> $HOME/oafe-install.log 2>&1 || return 1

    echoinfo "Enabling Draios repository for Sysdig"
    wget -q -O - https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | apt-key add -   >> $HOME/oafe-install.log 2>&1 || return 1
    wget -q --output-document /etc/apt/sources.list.d/draios.list http://download.draios.com/stable/deb/draios.list  >> $HOME/oafe-install.log 2>&1 || return 1

#    echoinfo "Enabling the REMnux repository"
#    add-apt-repository -y ppa:remnux/stable >> $HOME/oafe-install.log 2>&1 || return 1

    echoinfo "Enabling InetSim repository"
    wget -O - http://www.inetsim.org/inetsim-archive-signing-key.asc | apt-key add
    echo "deb http://www.inetsim.org/debian/ binary/" > /etc/apt/sources.list.d/inetsim.list

    echoinfo "Enabling the Oracle Java 8 repository, installing Java8, and setting Oracle Java8 as default java environment"
    add-apt-repository -y ppa:webupd8team/java >> $HOME/oafe-install.log 2>&1 || return 1
    echo debconf shared/accepted-oracle-license-v1-1 select true | debconf-set-selections >> $HOME/oafe-install.log 2>&1 || return 1
    echo debconf shared/accepted-oracle-license-v1-1 seen true | debconf-set-selections >> $HOME/oafe-install.log 2>&1 || return 1
    apt-get update >> $HOME/oafe-install.log 2>&1  || return 1
    apt-get install -y oracle-java8-installer
    update-java-alternatives -s java-8-oracle
    apt-get install -y oracle-java8-set-default

    echoinfo "Enabling the MaxMind GeoIP Repository"
    add-apt-repository -y ppa:maxmind/ppa >> $HOME/oafe-install.log 2>&1 || return 1

    echoinfo "Enabling the Cockpit Repository"
    add-apt-repository -y ppa:cockpit-project/cockpit

    echoinfo "Enabling Neo4j Repository"
    wget -O - https://debian.neo4j.org/neotechnology.gpg.key | sudo apt-key add -  >> $HOME/oafe-install.log || return 1
    echo 'deb http://debian.neo4j.org/repo stable/' >/tmp/neo4j.list
    mv /tmp/neo4j.list /etc/apt/sources.list.d  >> $HOME/oafe-install.log || return 1

    echoinfo "Enabling the Node.js repository"
    apt-key adv --keyserver keyserver.ubuntu.com --recv 68576280 >> $HOME/oafe-install.log || return 1
    apt-add-repository -y 'deb https://deb.nodesource.com/node_4.x precise main' >> $HOME/oafe-install.log || return 1

        echoinfo "Enabling GrayLog repository"
        wget https://packages.graylog2.org/repo/packages/graylog-2.0-repository_latest.deb  >> $HOME/oafe-install.log || return 1
        dpkg -i graylog-2.0-repository_latest.deb >> $HOME/oafe-install.log 2>&1  || return 1

#echoinfo "Enabling Puppet repository"
#        wget https://apt.puppetlabs.com/puppetlabs-release-trusty.deb  >> $HOME/oafe-install.log #|| return 1
#        dpkg -i puppetlabs-release-trusty.deb

    echoinfo "Enabling beats repository"
    echo "deb https://packages.elastic.co/beats/apt stable main" |  sudo tee -a /etc/apt/sources.list.d/beats.list >> $HOME/oafe-install.log || return 1
    wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - >> $HOME/oafe-install.log || return 1

    echoinfo "Updating Repository Package List ..."
    apt-get update >> $HOME/oafe-install.log 2>&1 || return 1

    echoinfo "Upgrading all packages to latest version ..."
    __apt_get_upgrade_noinput >> $HOME/oafe-install.log 2>&1 || return 1

    return 0
}

install_ubuntu_16.04_packages() {
    packages="aeskeyfind
afflib-tools
aircrack-ng
apache2
apt-transport-https
arp-scan
autoconf
automake
autopsy
bcrypt
binutils
binutils-dev
bison
bkhive
bless
blt
bridge-utils
bro
broctl
build-essential
bundler
byacc
cabextract
ccrypt
chromium-browser
clamav
clamav-daemon
cmospwd
cockpit
cryptcat
cryptsetup
curl
dc3dd
dcfldd
dconf-tools
debconf-utils
dh-autoreconf
dkms
docker-engine
docker.io
dos2unix
driftnet
dsniff
e2fslibs-dev
ent
epic5
etherape
ettercap-graphical
exfat-fuse
exfat-utils
exif
extundelete
fcgiwrap
fdupes
feh
firefox
flare
flasm
flex
foremost
g++
gawk
gcc
gdb
gddrescue
geany
genisoimage
geoipupdate
gettext
ghex
git
git-core
gparted
graphviz
gthumb
gtk2-engines:i386
guymager
gzrt
hexedit
htop
hydra
hydra-gtk
ibus
imagemagick
inetsim
inspircd
iptables-persistent
ipython
knocker
kpartx
lame
lft
lib32stdc++6
libafflib-dev
libbz2-dev
libc6-dev
libc6-dev-i386
libcanberra-gtk-module:i386
libcap-ng-dev
libcap-ng0
libcap2-bin
libcurl4-gnutls-dev
libcurl4-openssl-dev
libdate-simple-perl
libdatetime-perl
libemail-outlook-message-perl
libemu2
libewf-dev
libffi-dev
libfreetype6-dev
libfuse-dev
libfuzzy-dev
libgdbm-dev
libgeoip-dev
libgif-dev
libglib2.0
libgtk2.0-0:i386
libimage-exiftool-perl
libjansson-dev
libjavassist-java
libjpeg8-dev
libjpeg-dev
libjpeg-turbo8
libjpeg-turbo8-dev
libjson-perl
libldns1
libldns-dev
liblzma-dev
liblzma5
libmagic-dev
libmozjs-24-bin
libmysqlclient-dev
libncurses5-dev
libncurses5:i386
libnet1
libnet1-dev
libolecf-dev
libpam0g-dev
libparse-win32registry-perl
libpcap-dev
libpcre++-dev
libpcre3
libpcre3-dev
libpff-dev
libpng-dev
libpq-dev
libre2-dev
libreadline-gplv2-dev
libregf-dev
libsm6:i386
libsqlite3-dev
libssl-dev
libtext-csv-perl
libtool
libv8-dev
libvshadow-dev
libwebkitgtk-1.0-0
libwww-perl
libxml2
libxml2-dev
libxslt1.1
libxslt1-dev
libxxf86vm1:i386
libyaml-0-2
libyaml-dev
libyara3
libzmq3-dev
ltrace
make
masscan
md5deep
meld
mercurial
mongodb
mongodb-clients
mongodb-server
mosh
nbd-client
nbtscan
neo4j
netcat
netpbm
netsed
netwox
nfdump
ngrep
nikto
nmap
nodejs
ntopng
okular
open-iscsi
openssh-client
openssh-server
openssl
openvpn
ophcrack
ophcrack-cli
oracle-java8-installer
outguess
p0f
p7zip-full
passivedns
pdfresurrect
pdftk
pev
phantomjs
phonon
phpmyadmin
php7.0-gd
php7.0-fpm
pkg-config
pslist
puppet
pv
pwgen
pyew
python
python-bottle
python-bson
python-capstone
python-cffi
python-chardet
python-crypto
python-dev
python-dnspython
python-dpkt
python-fuse
python-gevent
python-gridfs
python-gtk2
python-gtk2-dev
python-gtksourceview2
python-hachoir-core
python-hachoir-metadata
python-hachoir-parser
python-hachoir-regex
python-hachoir-subfile
python-hachoir-urwid
python-hachoir-wx
python-ipy
python-jinja2
python-levenshtein
python-libvirt
python-m2crypto
python-magic
python-msgpack
python-mysqldb
python-nids
python-nose
python-numpy
python-pcapy
python-pefile
python-pil
python-pillow
python-pip
python-progressbar
python-pyasn1
python-pyclamd
python-pydot
python-pygal
python-pyrex
python-qt4
python-scipy
python-setuptools
python-socks
python-sqlalchemy
python-tk
python-utidylib
python-vte
python-whois
python-yara
python-zmq
qemu
qemu-utils
qpdf
radare2
rar
readpst
redis-server
rhino
rsakeyfind
ruby
ruby-dev
ruby-gtk2
safecopy
samba
samdump2
scalpel
schedtool
scite
sleuthkit
socat
spawn-fcgi
ssdeep
ssldump
sslsniff
strace
stunnel4
subversion
supervisor
swftools
swig
sysdig
system-config-samba
tcl
tcpdump
tcpflow
tcpick
tcpreplay
tcpstat
tcptrace
tcptrack
tcpxtract
tesseract-ocr
testdisk
tig
tofrodos
tor
torsocks
transmission
unhide
unicode
unity-control-center
unrar
upx-ucl
usbmount
uuid-dev
uwsgi
uwsgi-plugin-python
vbindiff
vim
virtualbox-5.1
virtuoso-minimal
vmfs-tools
volatility
winbind
wine
wireshark
wxhexeditor
xdot
xfsprogs
xmlstarlet
xmount
xpdf
xz-utils
zenity
zip
zlib1g
zlib1g-dev
zmap
filebeat
apache2-utils
mitmproxy"

    if [ "$@" = "dev" ]; then
        packages="$packages"
    elif [ "$@" = "stable" ]; then
        packages="$packages"
    fi

    for PACKAGE in $packages; do
        __apt_get_install_noinput $PACKAGE >> $HOME/oafe-install.log 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echoerror "Install Failure: $PACKAGE (Error Code: $ERROR)"
        else
            echoinfo "Installed Package: $PACKAGE"
        fi
    done

    return 0
}

install_ubuntu_16.04_pip_packages() {
    pip_packages="alembic==0.8.0 analyzeMFT argparse beautifulsoup4==4.4.1 bitstring bottle cffi==1.2.1 colorama construct cryptography==1.0 cybox distorm distorm3 django dnspython docopt dpkt ecdsa enum34 Flask Flask-SQLAlchemy fluent-logger fuzzywuzzy HTTPReplay idna interruptingcow ioc_writer ipaddress itsdangerous ivre javatools Jinja2 jsbeautifier lxml maec Mako MarkupSafe mitmproxy MySQL-python ndg-httpsclient olefile oletools pbkdf2 pexcept pefile PrettyTable psycopg2 py-unrar2 py3compat pyasn1 pycparser pycrypto pydeep pyelftools pylzma pymisp pymongo pypdns pype32 pyOpenSSL pypssl python-dateutil python-editor python-evtx python-magic python-registry pyv8 pyvmomi r2pipe rarfile rekall requesocks requests request-cache scandir scikit-learn six stix stix-validator SQLAlchemy terminaltables timesketch tlslite-ng unicodecsv virtualenv virustotal-api wakeonlan Werkzeug xortool"
    pip_pre_packages="bitstring"

    if [ "$@" = "dev" ]; then
        pip_packages="$pip_packages"
    elif [ "$@" = "stable" ]; then
        pip_packages="$pip_packages"
    fi

    ERROR=0
    for PACKAGE in $pip_pre_packages; do
        CURRENT_ERROR=0
        echoinfo "Installed Python (pre) Package: $PACKAGE"
        __pip_pre_install_noinput $PACKAGE >> $HOME/oafe-install.log 2>&1 || (let ERROR=ERROR+1 && let CURRENT_ERROR=1)
        if [ $CURRENT_ERROR -eq 1 ]; then
            echoerror "Python Package Install Failure: $PACKAGE"
        fi
    done

    for PACKAGE in $pip_packages; do
        CURRENT_ERROR=0
        echoinfo "Installed Python Package: $PACKAGE"
        __pip_install_noinput $PACKAGE >> $HOME/oafe-install.log 2>&1 || (let ERROR=ERROR+1 && let CURRENT_ERROR=1)
        if [ $CURRENT_ERROR -eq 1 ]; then
            echoerror "Python Package Install Failure: $PACKAGE"
        fi
    done

    if [ $ERROR -ne 0 ]; then
        echoerror
        return 1
    fi

    return 0
}


# Global: Works on 12.04 and 16.04
install_perl_modules() {
	# Required by macl.pl script
	perl -MCPAN -e "install Net::Wigle" >> $HOME/oafe-install.log 2>&1
	perl -MCPAN -e "install Net::Server" >> $HOME/oafe-install.log 2>&1
	perl -MCPAN -e "install Net::DNS" >> $HOME/oafe-install.log 2>&1
	perl -MCPAN -e "install IPC::Shareable" >> $HOME/oafe-install.log 2>&1
	perl -MCPAN -e "install Digest::SHA" >> $HOME/oafe-install.log 2>&1
	perl -MCPAN -e "install IO::Socket::SSL" >> $HOME/oafe-install.log 2>&1
}


install_sift_files() {
  # Checkout code from sift-files and put these files into place
  echoinfo "OAFE VM: Installing SANS SIFT Files"
	CDIR=$(pwd)
	git clone --recursive https://github.com/sans-dfir/sift-files /tmp/sift-files >> $HOME/oafe-install.log 2>&1
	cd /tmp/sift-files
	bash install.sh >> $HOME/oafe-install.log 2>&1
	cd $CDIR
	rm -r -f /tmp/sift-files
}

#update_clamav_signatures() {
    #if [ -e /usr/bin/freshclam ]; then
    #  echoinfo "Updating ClamAV Signatures"
    #  freshclam --quiet
    #fi
#}

configure_ubuntu() {
echoinfo "Creating oafe directory in /opt/oafe"
    if [ ! -d /opt/oafe ]; then
        mkdir -p /opt/oafe
        chown $SUDO_USER:$SUDO_USER /opt/oafe
        chmod 775 /opt/oafe
        chmod g+s /opt/oafe
    fi

echoinfo "Cloning Optum OAFE support files to /opt/oafe/oafeubuntu"
    git clone https://github.com/rebaker501/oafeubuntu.git /opt/oafe/oafeubuntu
    chown -R $SUDO_USER:$SUDO_USER /opt/oafe/oafeubuntu
    chmod -R 775 /opt/oafe/oafeubuntu
    chmod -R g+s /opt/oafe/oafeubuntu

echoinfo "Setting OpenVPN to autostart and autorestart"
    cp /opt/oafe/oafeubuntu/conf/openvpn/openvpn /etc/default/openvpn
    cp /opt/oafe/oafeubuntu/conf/openvpn/openvpn@.service /lib/systemd/system/openvpn@.service

echoinfo "Enabling Cockpit Monitoring Service on port 9090"
    systemctl enable --now cockpit.socket

echoinfo "Enabling NGINX Firewall"
    ufw allow 'Nginx Full'
    systemctl disable apache2
    systemctl enable nginx
    mkdir /etc/nginx/ssl
    echoinfo "OpenSSL Certificate Creation - You will need to enter the details of the server here"
    openssl req -x509 -nodes -days 1460 -newkey rsa:2048 -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt
    openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
    echoinfo "Please type cfi password and verify"
    htpasswd -c /etc/nginx/conf.d/oafe.htpasswd cfi
    cp /opt/oafe/oafeubuntu/conf/nginx/default-nginx /etc/nginx/sites-available/default

echoinfo "Creating GeoIP config and downloading current databases"
    cp /opt/oafe/oafeubuntu/conf/GeoIP/GeoIP.conf /etc/GeoIP.conf >> $HOME/oafe-install.log || return 1
    geoipupdate >> $HOME/oafe-install.log || return 1

echoinfo "Installing Elasticsearch, Kibana, Logstash, and Graylog as services"
    if [ ! -d /opt/oafe/oafeubuntu/Packages/ ]; then
        mkdir -p /opt/oafe/oafeubuntu/Packages/
        chown cfi:cfi /opt/oafe/oafeubuntu/Packages/
        chmod -R 775 /opt/oafe/oafeubuntu/Packages/
        chmod -R g+s /opt/oafe/oafeubuntu/Packages/
    fi
    dpkg -i /opt/oafe/oafeubuntu/Packages/elasticsearch-2.4.1.deb
    dpkg -i /opt/oafe/oafeubuntu/Packages/logstash-2.4.0_all.deb
    dpkg -i /opt/oafe/oafeubuntu/Packages/kibana-4.6.1-amd64.deb
    mkdir -p /etc/logstash/conf.d/bro
    mkdir -p /etc/logstash/conf.d/kansa
    mkdir -p /etc/logstash/conf.d/maltrail
    mkdir -p /etc/logstash/conf.d/passivedns
    cp /opt/oafe/oafeubuntu/conf/logstash/ingest/logstash_kansa_ingest.conf /etc/logstash/conf.d/kansa/logstash_kansa_ingest.conf >> $HOME/oafe-install.log
    cp /opt/oafe/oafeubuntu/conf/logstash/ingest/bro-appstats.conf /opt/logstash/  >> $HOME/oafe-install.log
    cp /opt/oafe/oafeubuntu/conf/logstash/ingest/bro-dns.conf /opt/logstash/  >> $HOME/oafe-install.log
    cp /opt/oafe/oafeubuntu/conf/logstash/ingest/bro-files.conf /opt/logstash/  >> $HOME/oafe-install.log
    cp /opt/oafe/oafeubuntu/conf/logstash/ingest/bro-weird.conf /opt/logstash/  >> $HOME/oafe-install.log
    cp /opt/oafe/oafeubuntu/conf/logstash/ingest/sensor.conf /opt/logstash/  >> $HOME/oafe-install.log
    cp /opt/oafe/oafeubuntu/conf/logstash/ingest/start /opt/logstash/  >> $HOME/oafe-install.log
    cp /opt/oafe/oafeubuntu/conf/logstash/ingest/stop /opt/logstash/  >> $HOME/oafe-install.log
    #moving over rc.local file
    cp /etc/rc.local /etc/rc.local.backup >> $HOME/oafe-install.log
    cp /opt/oafe/oafeubuntu/etc/rc.local /etc/rc.local >> $HOME/oafe-install.log
    systemctl daemon-reload
    systemctl enable elasticsearch
    systemctl enable kibana
    systemctl enable logstash
    systemctl start elasticsearch
    sleep 1m
    apt-get install graylog-server
    systemctl enable graylog-server
    systemctl start kibana
    systemctl start logstash
    systemctl start logstashingest
    systemctl start graylog-server
    update-rc.d graylog-server defaults 96 9
    /usr/share/elasticsearch/bin/plugin install mobz/elasticsearch-head
    /usr/share/elasticsearch/bin/plugin install jayant2014/bigdesk
    /usr/share/elasticsearch/bin/plugin install lmenezes/elasticsearch-kopf/2.x
    rm -f /etc/init/graylog-server.override
    SECRET=$(pwgen -s 96 1)
    sudo -E sed -i -e 's/password_secret =.*/password_secret = '$SECRET'/' /etc/graylog/server/server.conf
    PASSWORD=$(echo -n admin | shasum -a 256 | awk '{print $1}')
    sudo -E sed -i -e 's/root_password_sha2 =.*/root_password_sha2 = '$PASSWORD'/' /etc/graylog/server/server.conf
    service graylog-server start
    sudo ln -s /opt/logstash/bin/logstash /usr/bin/logstash >> $HOME/oafe-install.log 2>&1
    sudo ln -s /opt/logstash/bin/logstash-plugin /usr/bin/logstash-plugin >> $HOME/oafe-install.log 2>&1
    sudo ln -s /opt/logstash/bin/logstash.lib.sh /usr/bin/logstash.lib.sh >> $HOME/oafe-install.log 2>&1
    logstash-plugin install logstash-filter-translate >> $HOME/oafe-install.log 2>&1

echoinfo "Starting BRO IDS"
    cp /opt/oafe/oafeubuntu/conf/bro/node.cfg /etc/bro/node.cfg >> $HOME/oafe-install.log
    broctl deploy >> $HOME/oafe-install.log 2>&1
    cp /opt/oafe/oafeubuntu/etc/cron.d/broctl /etc/cron.d/broctl >> $HOME/oafe-install.log

echoinfo "Installing Cuckoo Sandbox"
        if [ ! -d /opt/oafe/VMs ]; then
		mkdir -p /opt/oafe/VMs
		chown $SUDO_USER:$SUDO_USER /opt/oafe/VMs
	 	chmod -R 775 /opt/oafe/VMs
		chmod -R g+s /opt/oafe/VMs
	fi
        if [ ! -d /opt/oafe/cuckoodeps ]; then
		mkdir -p /opt/oafe/cuckoodeps
		chown $SUDO_USER:$SUDO_USER /opt/oafe/cuckoodeps
	 	chmod -R 775 /opt/oafe/cuckoodeps
		chmod -R g+s /opt/oafe/cuckoodeps
	fi
        if [ ! -d /var/log/cuckooweb ]; then
		mkdir -p /var/log/cuckooweb
		chown $SUDO_USER:$SUDO_USER /var/log/cuckooweb
	 	chmod -R 775 /var/log/cuckooweb
		chmod -R g+s /var/log/cuckooweb
	fi
        if [ ! -d /var/log/cuckoo ]; then
		mkdir -p /var/log/cuckoo
		chown $SUDO_USER:$SUDO_USER /var/log/cuckoo
	 	chmod -R 775 /var/log/cuckoo
		chmod -R g+s /var/log/cuckoo
	fi
        if [ ! -d /var/log/cuckooapi ]; then
		mkdir -p /var/log/cuckooapi
		chown $SUDO_USER:$SUDO_USER /var/log/cuckooapi
	 	chmod -R 775 /var/log/cuckooapi
		chmod -R g+s /var/log/cuckooapi
	fi
    	echoinfo "Type cuckoo user password and verify"
        adduser cuckoo
        usermod -a -G vboxusers cuckoo
        usermod -a -G vboxusers cfi
        wget -O /opt/oafe/cuckoodeps/distorm3.zip https://github.com/gdabah/distorm/archive/v3.3.0.zip
        wget -O /opt/oafe/cuckoodeps/pycrypto-2.6.1.tar.gz https://ftp.dlitz.net/pub/dlitz/crypto/pycrypto/pycrypto-2.6.1.tar.gz
        wget -O /opt/oafe/cuckoodeps/yara-v3.4.0.tar.gz https://github.com/plusvic/yara/archive/v3.4.0.tar.gz
        wget -O /opt/oafe/cuckoodeps/setuptools-5.7.tar.gz https://pypi.python.org/packages/source/s/setuptools/setuptools-5.7.tar.gz
        wget -O /opt/oafe/cuckoodeps/openpyxl-2.3.0.tar.gz https://bitbucket.org/openpyxl/openpyxl/get/2.3.0.tar.gz
        wget -O /opt/oafe/cuckoodeps/ipython-2.4.1.tar.gz https://pypi.python.org/packages/source/i/ipython/ipython-2.4.1.tar.gz
        wget -O /opt/oafe/cuckoodeps/volatility-2.5.tar.gz https://github.com/volatilityfoundation/volatility/archive/2.5.tar.gz
        cd /opt/oafe/cuckoodeps
        unzip distorm3.zip
        tar xvfz pycrypto-2.6.1.tar.gz
        tar xvfz yara-v3.4.0.tar.gz
        tar xvfz setuptools-5.7.tar.gz
        tar xvfz openpyxl-2.3.0.tar.gz
        tar xvfz ipython-2.4.1.tar.gz
        tar xvfz volatility-2.5.tar.gz
        cd /opt/oafe/cuckoodeps/distorm-3.3.0
        python setup.py build install
        cd /opt/oafe/cuckoodeps/yara-3.4.0
        chmod +x bootstrap.sh && ./bootstrap.sh && ./configure --enable-magic --enable-cuckoo ; make ; make install
        cd yara-python && python setup.py build install && ldconfig && cd /opt/oafe/cuckoodeps
        cd /opt/oafe/cuckoodeps/setuptools-5.7 && python ez_setup.py && cd /opt/oafe/cuckoodeps
        cd openpyxl-openpyxl-17ebc853f530 && python setup.py build install && cd /opt/oafe/cuckoodeps
        easy_install --upgrade pytz
        cd ipython-2.4.1 && python setup.py build install && cd /opt/oafe/cuckoodeps
        mv -f volatility-2.5 .. ; cd ../volatility-2.5 && chmod +x vol.py
        ln -f -s "${PWD}"/vol.py /usr/local/bin/vol.py
        mysql -uroot -pchangeme! -e "CREATE DATABASE cuckoo" >> $HOME/oafe-install.log || return 1
        mysql -uroot -pchangeme! -e "GRANT ALL PRIVILEGES ON *.* TO cuckoo@localhost IDENTIFIED BY 'changeme!'" >> $HOME/oafe-install.log || return 1
        mysql -uroot -pchangeme! -e "FLUSH PRIVILEGES" >> $HOME/oafe-install.log || return 1
        git clone https://github.com/cuckoosandbox/cuckoo /opt/oafe/cuckoo
        chmod -R 775 /opt/oafe/cuckoo  >> $HOME/oafe-install.log || return 1
        chmod -R g+s /opt/oafe/cuckoo  >> $HOME/oafe-install.log || return 1
        if [ ! -d /opt/oafe/cuckoo/uwsgi ]; then
        	mkdir -p /opt/oafe/cuckoo/uwsgi
        	chown $SUDO_USER:$SUDO_USER /opt/oafe/cuckoo/uwsgi
        	chmod -R 775 /opt/oafe/cuckoo/uwsgi
        	chmod -R g+s /opt/oafe/cuckoo/uwsgi
    	fi
        vboxmanage hostonlyif create >> $HOME/oafe-install.log || return 1
        ip link set vboxnet0 up >> $HOME/oafe-install.log || return 1
	ip addr add 192.168.56.1/24 dev vboxnet0
        cp /opt/oafe/oafeubuntu/conf/cuckoo/rules.v4 /etc/iptables/rules.v4 >> $HOME/oafe-install.log || return 1
        sysctl -w net.ipv4.ip_forward=1 >> $HOME/oafe-install.log || return 1
        setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump >> $HOME/oafe-install.log || return 1
        cp /opt/oafe/oafeubuntu/conf/supervisor/supervisord.conf /etc/supervisor/supervisord.conf>> $HOME/oafe-install.log || return 1
        cp /opt/oafe/oafeubuntu/conf/cuckoo/sysctl.conf /etc/sysctl.conf >> $HOME/oafe-install.log || return 1
        cp /opt/oafe/oafeubuntu/conf/cuckoo/django.ini /opt/oafe/cuckoo/uwsgi/django.ini >> $HOME/oafe-install.log || return 1
        cp /opt/oafe/oafeubuntu/conf/cuckoo/api.ini /opt/oafe/cuckoo/uwsgi/api.ini >> $HOME/oafe-install.log || return 1
        cp /opt/oafe/oafeubuntu/conf/cuckoo/cuckoo.conf /opt/oafe/cuckoo/conf/cuckoo.conf >> $HOME/oafe-install.log || return 1
        cp /opt/oafe/oafeubuntu/conf/cuckoo/processing.conf /opt/oafe/cuckoo/conf/processing.conf >> $HOME/oafe-install.log || return 1
        cp /opt/oafe/oafeubuntu/conf/cuckoo/auxiliary.conf /opt/oafe/cuckoo/conf/auxiliary.conf >> $HOME/oafe-install.log || return 1
        cp /opt/oafe/oafeubuntu/conf/cuckoo/memory.conf /opt/oafe/cuckoo/conf/memory.conf >> $HOME/oafe-install.log || return 1
        cp /opt/oafe/oafeubuntu/conf/cuckoo/reporting.conf /opt/oafe/cuckoo/conf/reporting.conf >> $HOME/oafe-install.log || return 1
        cp /opt/oafe/oafeubuntu/conf/cuckoo/virtualbox.conf /opt/oafe/cuckoo/conf/virtualbox.conf >> $HOME/oafe-install.log || return 1
        python /opt/oafe/cuckoo/utils/community.py -a -f -w >> $HOME/oafe-install.log || return 1
        systemctl daemon-reload >> $HOME/oafe-install.log || return 1
        systemctl restart supervisor >> $HOME/oafe-install.log || return 1

echoinfo "Installing Maltrail"
        if [ ! -d /opt/oafe/maltrail ]; then
		mkdir -p /opt/oafe/maltrail
		chown $SUDO_USER:$SUDO_USER /opt/oafe/maltrail
		chmod -R 775 /opt/oafe/maltrail
		chmod -R g+s /opt/oafe/maltrail
	fi
        if [ ! -d /var/log/maltrailsensor ]; then
		mkdir -p /var/log/maltrailsensor
		chown $SUDO_USER:$SUDO_USER /var/log/maltrailsensor
		chmod -R 775 /var/log/maltrailsensor
		chmod -R g+s /var/log/maltrailsensor
	fi
        if [ ! -d /var/log/maltrailserver ]; then
		mkdir -p /var/log/maltrailserver
		chown $SUDO_USER:$SUDO_USER /var/log/maltrailserver
		chmod -R 775 /var/log/maltrailserver
		chmod -R g+s /var/log/maltrailserver
	fi
        git clone https://github.com/stamparm/maltrail.git /opt/oafe/maltrail >> $HOME/oafe-install.log 2>&1
        cp /opt/oafe/oafeubuntu/conf/supervisor/maltrailsensor_supervisor.conf /etc/supervisor/conf.d/maltrailsensor_supervisor.conf >> $HOME/oafe-install.log || return 1
        cp /opt/oafe/oafeubuntu/conf/systemd/maltrailserver.service /etc/systemd/system/maltrailserver.service >> $HOME/oafe-install.log || return 1
        cp /opt/oafe/oafeubuntu/conf/maltrail/maltrail.conf /opt/oafe/maltrail/maltrail.conf >> $HOME/oafe-install.log || return 1
        systemctl daemon-reload >> $HOME/oafe-install.log || return 1
        systemctl enable supervisor >> $HOME/oafe-install.log || return 1
        systemctl enable maltrailserver >> $HOME/oafe-install.log || return 1

echoinfo "Installing Moloch DPI"
	systemctl start elasticsearch
	sleep 1m
	wget -O /opt/oafe/oafeubuntu/Packages/moloch_0.16.0-1_amd64.deb http://files.molo.ch/builds/ubuntu-16.04/moloch_0.16.0-1_amd64.deb
	dpkg -i /opt/oafe/oafeubuntu/Packages/moloch_0.16.0-1_amd64.deb
	echoinfo "Please choose your capture interface.  On DL380G9, this is eno1"
	/data/moloch/bin/Configure
	/data/moloch/db/db.pl http://localhost:9200 init
	/data/moloch/bin/moloch_add_user.sh admin admin changeme! --admin
	cp /opt/oafe/oafeubuntu/conf/moloch/config.ini /data/moloch/etc/config.ini
	systemctl daemon-reload
	systemctl enable molochcapture
	systemctl enable molochviewer
	sleep 1m
	systemctl start molochcapture.service
	systemctl start molochviewer.service

echoinfo "Enabling Google Rapid Response Installer"
        if [ ! -d /opt/oafe/grr ]; then
		mkdir -p /opt/oafe/grr
		chown $SUDO_USER:$SUDO_USER /opt/oafe/grr
		chmod -R 775 /opt/oafe/grr
		chmod -R g+s /opt/oafe/grr
	fi
        wget -O /opt/oafe/grr/install_google_rapid_response.sh https://raw.githubusercontent.com/google/grr/master/scripts/install_script_ubuntu.sh  >> $HOME/oafe-install.log || return 1
        chmod -c 775 /opt/oafe/grr/install_google_rapid_response.sh >> $HOME/oafe-install.log || return 1

echoinfo "Installing PassiveDNS"
    if [ ! -d /var/log/passivedns ]; then
	mkdir -p /var/log/passivedns
	chown $SUDO_USER:$SUDO_USER /var/log/passivedns
	chmod 775 /var/log/passivedns
	chmod g+s /var/log/passivedns
    fi
    if [ ! -d /var/log/passivedns/data ]; then
	mkdir -p /var/log/passivedns/data
	chown $SUDO_USER:$SUDO_USER /var/log/passivedns/data
	chmod -R 777 /var/log/passivedns/data
	chmod g+s /var/log/passivedns/data
    fi
    cp /opt/oafe/oafeubuntu/conf/logstash/ingest/logstash_passivednsingest.conf /etc/logstash/conf.d/logstash_passivednsingest.conf >> $HOME/oafe-install.log || return 1
    cp /opt/oafe/oafeubuntu/conf/systemd/passivedns.service /etc/systemd/system/passivedns.service >> $HOME/oafe-install.log || return 1
        systemctl daemon-reload  >> $HOME/oafe-install.log || return 1
        systemctl enable passivedns  >> $HOME/oafe-install.log || return 1

echoinfo "Install Kansa Files for Threat Hunting"
    if [ ! -d /opt/oafe/moloch ]; then
        mkdir -p /opt/oafe/kansa
        chown $SUDO_USER:$SUDO_USER /opt/oafe/kansa
        chmod -R 775 /opt/oafe/kansa
        chmod -R g+s /opt/oafe/kansa
    fi
    cp /opt/oafe/oafeubuntu/conf/logstash/ingest/logstash_kansa_ingest.conf /etc/logstash/conf.d/logstash_kansa_ingest.conf
    git clone https://github.com/davehull/Kansa /opt/oafe/kansa

echoinfo "Install Kibi"
    chmod -R 775 /opt/oafe/
    wget -O /opt/oafe/kibi-4.5.3-3-linux-x64.zip https://download.support.siren.solutions/kibi/community?file=kibi-4.5.3-3-linux-x64.zip
    chmod 777 /opt/oafe/kibi-4.5.3-3-linux-x64.zip  >> $HOME/oafe-install.log || return 1
    unzip /opt/oafe/kibi-4.5.3-3-linux-x64.zip -d /opt/oafe/ >> $HOME/oafe-install.log || return 1
    mv /opt/oafe/kibi-4.5.3-3-linux-x64 /opt/oafe/kibi  >> $HOME/oafe-install.log || return 1
    chmod -R 777 /opt/oafe/kibi  >> $HOME/oafe-install.log || return 1
    chown cfi:cfi /opt/oafe/kibi  >> $HOME/oafe-install.log || return 1
    chmod g+s /opt/oafe/kibi  >> $HOME/oafe-install.log || return 1
    cp /opt/oafe/oafeubuntu/conf/systemd/kibi.service /etc/systemd/system/kibi.service  >> $HOME/oafe-install.log || return 1
    /opt/oafe/kibi/bin/kibi plugin -i kibana-html-plugin -u https://github.com/raystorm-place/kibana-html-plugin/releases/download/v0.0.3/kibana-html-plugin-v0.0.3.tar.gz
    systemctl daemon-reload  >> $HOME/oafe-install.log || return 1
    systemctl enable kibi  >> $HOME/oafe-install.log || return 1
    systemctl start kibi  >> $HOME/oafe-install.log || return 1

echoinfo "Install VNC Server"
    if [ ! -d /opt/oafe/vncserver ]; then
        mkdir -p /opt/oafe/vncserver
        chown $SUDO_USER:$SUDO_USER /opt/oafe/vncserver
        chmod 775 /opt/oafe/vncserver
        chmod g+s /opt/oafe/vncserver
    fi
    wget https://www.dropbox.com/s/robkv82p2xv0hfh/VNC-Server-5.3.2-Linux-x64.deb?dl=0 -O /opt/oafe/vncserver/VNCServer5.3.2x64.deb
    wget https://www.dropbox.com/s/ft4cjk8hqbo2562/VNC-Viewer-5.3.2-Linux-x64.deb?dl=0 -O /opt/oafe/vncserver/VNCViewer5.3.2x64.deb
    dpkg -i /opt/oafe/vncserver/VNCServer5.3.2x64.deb  >> $HOME/oafe-install.log || return 1
    dpkg -i /opt/oafe/vncserver/VNCViewer5.3.2x64.deb  >> $HOME/oafe-install.log || return 1
    vnclicense -add JBBA2-64NYS-4Q322-3HTGZ-LU3NA
    systemctl enable vncserver-x11-serviced.service  >> $HOME/oafe-install.log || return 1
    systemctl start vncserver-virtuald.service  >> $HOME/oafe-install.log || return 1

echoinfo "Install Viper Framework"
    git clone https://github.com/viper-framework/viper /opt/oafe/viper >> $HOME/oafe-install.log || return 1
    chmod -R 775 /opt/oafe/viper >> $HOME/oafe-install.log || return 1
    chown cfi:cfi /opt/oafe/viper >> $HOME/oafe-install.log || return 1
    chmod g+s /opt/oafe/viper >> $HOME/oafe-install.log || return 1
    cp /opt/oafe/oafeubuntu/conf/systemd/viperweb.service /etc/systemd/system/viperweb.service >> $HOME/oafe-install.log || return 1
    cp /opt/oafe/oafeubuntu/conf/systemd/viper.service /etc/systemd/system/viper.service >> $HOME/oafe-install.log || return 1

echoinfo "Set Launcher Shortcuts"
    sudo -u cfi gsettings set com.canonical.Unity.Launcher favorites "['application://nautilus.desktop', 'application://gnome-terminal.desktop', 'application://firefox.desktop', 'application://gnome-screenshot.desktop', 'application://chromium-browser.desktop', 'application://gedit.desktop', 'application://wireshark.desktop', 'application://virtualbox.desktop', 'application://geany.desktop', 'application://unity-control-center.desktop', 'application://remmina.desktop', 'application://gnome-system-monitor', 'application://guymager.desktop']" >> $HOME/oafe-install.log 2>&1

echoinfo "Enabling autostart services"
    systemctl daemon-reload >> $HOME/oafe-install.log || return 1
    systemctl enable viperweb >> $HOME/oafe-install.log || return 1
    systemctl enable viper >> $HOME/oafe-install.log || return 1

echoinfo "OAFE VM: Creating Cases Folder"
    if [ ! -d /cases ]; then
	mkdir -p /cases
	chown $SUDO_USER:$SUDO_USER /cases
	chmod 775 /cases
	chmod g+s /cases
    fi

echoinfo "OAFE VM: Creating Mount Folders"
    for dir in usb vss shadow windows_mount e01 aff ewf bde iscsi
    do
	if [ ! -d /mnt/$dir ]; then
	    mkdir -p /mnt/$dir
	fi
    done

    for NUM in 1 2 3 4 5
    do
	if [ ! -d /mnt/windows_mount$NUM ]; then
		mkdir -p /mnt/windows_mount$NUM
	fi
	if [ ! -d /mnt/ewf_mount$NUM ]; then
		mkdir -p /mnt/ewf_mount$NUM
	fi
    done

    for NUM in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30
    do
	if [ ! -d /mnt/shadow/vss$NUM ]; then
		mkdir -p /mnt/shadow/vss$NUM
	fi
	if [ ! -d /mnt/shadow_mount/vss$NUM ]; then
		mkdir -p /mnt/shadow_mount/vss$NUM
	fi
    done

echoinfo "OAFE VM: Setting up symlinks to useful scripts"
    if [ ! -L /usr/bin/vol.py ] && [ ! -e /usr/bin/vol.py ]; then
        ln -s /usr/bin/vol.py /usr/bin/vol
    fi
    if [ ! -L /usr/bin/log2timeline ] && [ ! -e /usr/bin/log2timeline ]; then
	ln -s /usr/bin/log2timeline_legacy /usr/bin/log2timeline
    fi
    if [ ! -L /usr/bin/kedit ] && [ ! -e /usr/bin/kedit ]; then
	ln -s /usr/bin/gedit /usr/bin/kedit
    fi
    if [ ! -L /usr/bin/mount_ewf.py ] && [ ! -e /usr/bin/mount_ewf.py ]; then
	ln -s /usr/bin/ewfmount /usr/bin/mount_ewf.py
    fi

# Fix for https://github.com/sans-dfir/sift/issues/10
    if [ ! -L /usr/bin/icat-sleuthkit ] && [ ! -e /usr/bin/icat-sleuthkit ]; then
        ln -s /usr/bin/icat /usr/bin/icat-sleuthkit
    fi

# Fix for https://github.com/sans-dfir/sift/issues/23
    if [ ! -L /usr/local/bin/l2t_process ] && [ ! -e /usr/local/bin/l2t_process ]; then
        ln -s /usr/bin/l2t_process_old.pl /usr/local/bin/l2t_process
    fi

    if [ ! -L /usr/local/etc/foremost.conf ]; then
        ln -s /etc/foremost.conf /usr/local/etc/foremost.conf
    fi

# Fix for https://github.com/sans-dfir/sift/issues/41
    if [ ! -L /usr/local/bin/mactime-sleuthkit ] && [ ! -e /usr/local/bin/mactime-sleuthkit ]; then
        ln -s /usr/bin/mactime /usr/local/bin/mactime-sleuthkit
    fi

    sed -i "s/APT::Periodic::Update-Package-Lists \"1\"/APT::Periodic::Update-Package-Lists \"0\"/g" /etc/apt/apt.conf.d/10periodic

echoinfo "Install LaikaBoss"
    if [ ! -d /opt/oafe/laikaboss ]; then
        mkdir -p /opt/oafe/laikaboss
        chown $SUDO_USER:$SUDO_USER /opt/oafe/laikaboss
        chmod -R 775 /opt/oafe/laikaboss
        chmod -R g+s /opt/oafe/laikaboss
    fi
    wget -O /opt/oafe/master.zip https://github.com/smarnach/pyexiftool/archive/master.zip  >> $HOME/oafe-install.log || return 1
    unzip /opt/oafe/master.zip -d /opt/oafe/  >> $HOME/oafe-install.log || return 1
    chmod -R 775 /opt/oafe/pyexiftool-master
    chown cfi:cfi /opt/oafe/pyexiftool-master/
    cd /opt/oafe/pyexiftool-master/
    python setup.py build  >> $HOME/oafe-install.log || return 1
    python setup.py install  >> $HOME/oafe-install.log || return 1
    git clone https://github.com/lmco/laikaboss /opt/oafe/laikaboss >> $HOME/oafe-install.log || return 1
    sudo chmod -R 775 /opt/oafe/laikaboss  >> $HOME/oafe-install.log || return 1
    chown cfi:cfi /opt/oafe/laikaboss
    cd /opt/oafe/laikaboss/
    python setup.py build  >> $HOME/oafe-install.log || return 1
    python setup.py install  >> $HOME/oafe-install.log || return 1

    echoinfo "Start IVRE Depedencies"
    #start IVRE web interface required services
    echoinfo "starting php7.0-fpm service"
    service php7.0-fpm start
    echoinfo "starting fcgiwrap service"
    service fcgiwrap start

    #adding webmin, this will require a reboot and for you to enter in some default information
    echoinfo "Downloading and setting up webmin, do not enable ssh, we will configure this through nginx later"
    cd /opt/oafe/oafeubuntu/
    git clone https://github.com/webmin/webmin.git
    cd webmin
    ./setup.sh
    cp /opt/oafe/oafeubuntu/conf/webmin/conf /etc/webmin/conf >> $HOME/oafe-install.log
    cp /opt/oafe/oafeubuntu/conf/webmin/miniserv.conf /etc/webmin/miniserv.conf >> $HOME/oafe-install.log

    #fixing permissions for systemd services, they should be set to 644
    sudo chmod 0644 /etc/systemd/system/kibi.service
    sudo chmod 0644 /etc/systemd/system/passivedns.service
    sudo chmod 0644 /etc/systemd/system/viperweb.service
    sudo chmod 0644 /etc/systemd/system/viper.service
    sudo chmod 0644 /etc/systemd/system/maltrailserver.service
    sudo chmod 0644 /etc/systemd/system/logstashingest.service
}

# Global: Ubuntu SIFT VM Configuration Function
# Works with 12.04 and 16.04 Versions
configure_ubuntu_sift_vm() {

  echoinfo "OAFE VM: Fixing Samba User"
	# Make sure we replace the SIFT_USER template with our actual
	# user so there is write permissions to samba.
	sed -i "s/SIFT_USER/$SUDO_USER/g" /etc/samba/smb.conf

  echoinfo "OAFE VM: Restarting Samba"
	# Restart samba services
	service smbd restart >> $HOME/oafe-install.log 2>&1
	service nmbd restart >> $HOME/oafe-install.log 2>&1

  echoinfo "OAFE VM: Setting Timezone to UTC" >> $HOME/oafe-install.log 2>&1
  echo "America/New_York" > /etc/timezone >> $HOME/oafe-install.log 2>&1

  echoinfo "Setting Launcher"
  sudo -u cfi gsettings set com.canonical.Unity.Launcher favorites "['application://nautilus.desktop', 'application://gnome-terminal.desktop', 'application://firefox.desktop', 'application://gnome-screenshot.desktop', 'application://chromium-browser.desktop', 'application://gedit.desktop', 'application://wireshark.desktop', 'application://virtualbox.desktop', 'application://geany.desktop', 'application://unity-control-center.desktop', 'application://remmina.desktop', 'application://gnome-system-monitor', 'application://guymager.desktop']" >> $HOME/oafe-install.log 2>&1

  echoinfo "OAFE VM: Fixing Regripper Files"
	# Make sure to remove all ^M from regripper plugins
	# Not sure why they are there in the first place ...
	dos2unix -ascii /usr/share/regripper/* >> $HOME/oafe-install.log 2>&1

  if [ -f /usr/share/regripper/plugins/usrclass-all ]; then
    mv /usr/share/regripper/plugins/usrclass-all /usr/share/regripper/plugins/usrclass
  fi

  if [ -f /usr/share/regripper/plugins/ntuser-all ]; then
    mv /usr/share/regripper/plugins/ntuser-all /usr/share/regripper/plugins/ntuser
  fi

  chmod 775 /usr/share/regripper/rip.pl
  chmod -R 755 /usr/share/regripper/plugins

  echoinfo "OAFE VM: Setting noclobber for $SUDO_USER"
	if ! grep -i "set -o noclobber" $HOME/.bashrc > /dev/null 2>&1
	then
		echo "set -o noclobber" >> $HOME/.bashrc
	fi
	if ! grep -i "set -o noclobber" /root/.bashrc > /dev/null 2>&1
	then
		echo "set -o noclobber" >> /root/.bashrc
	fi

  echoinfo "OAFE VM: Configuring Aliases for $SUDO_USER and root"
	if ! grep -i "alias mountwin" $HOME/.bash_aliases > /dev/null 2>&1
	then
		echo "alias mountwin='mount -o ro,loop,show_sys_files,streams_interface=windows'" >> $HOME/.bash_aliases
	fi

	# For SIFT VM, root is used frequently, set the alias there too.
	if ! grep -i "alias mountwin" /root/.bash_aliases > /dev/null 2>&1
	then
		echo "alias mountwin='mount -o ro,loop,show_sys_files,streams_interface=windows'" >> /root/.bash_aliases
	fi

  echoinfo "OAFE VM: Sanity check for Desktop folder"
        if [ ! -d $HOME/Desktop ]; then
                sudo -u $SUDO_USER mkdir -p $HOME/Desktop
        fi

  echoinfo "OAFE VM: Setting up useful links on $SUDO_USER Desktop"
	if [ ! -L $HOME/Desktop/cases ]; then
		sudo -u $SUDO_USER ln -s /cases $HOME/Desktop/cases
	fi

	if [ ! -L $HOME/Desktop/mount_points ]; then
		sudo -u $SUDO_USER ln -s /mnt $HOME/Desktop/mount_points
	fi

  echoinfo "OAFE VM: Cleaning up broken symlinks on $SUDO_USER Desktop"
	# Clean up broken symlinks
	find -L $HOME/Desktop -type l -delete

  echoinfo "SIFT VM: Adding all SIFT Resources to $SUDO_USER Desktop"
	for file in /usr/share/sift/resources/*.pdf
	do
		base=`basename $file`
		if [ ! -L $HOME/Desktop/$base ]; then
			sudo -u $SUDO_USER ln -s $file $HOME/Desktop/$base
		fi
	done

  if [ ! -L /sbin/iscsiadm ]; then
    ln -s /usr/bin/iscsiadm /sbin/iscsiadm
  fi

  if [ ! -L /usr/local/bin/rip.pl ]; then
    ln -s /usr/share/regripper/rip.pl /usr/local/bin/rip.pl
  fi

  # Add extra device loop backs.
  if ! grep "do mknod /dev/loop" /etc/rc.local > /dev/null 2>&1
  then
    echo 'for i in `seq 8 100`; do mknod /dev/loop$i b 7 $i; done' >> /etc/rc.local
  fi
}

# 16.04 OAFE VM Configuration Function
configure_ubuntu_16.04_sift_vm() {
  sudo -u $SUDO_USER gsettings set com.canonical.Unity.Launcher favorites "['application://nautilus.desktop', 'application://gnome-terminal.desktop', 'application://firefox.desktop', 'application://gnome-screenshot.desktop', 'application://gcalctool.desktop', 'application://bless.desktop', 'application://autopsy.desktop', 'application://wireshark.desktop']" >> $HOME/oafe-install.log 2>&1

  # Works in 12.04 and 16.04
  sudo -u $SUDO_USER gsettings set org.gnome.desktop.background picture-uri file:///opt/oafe/oafeubuntu/branding/OAFE_Background_1920_1080.jpg >> $HOME/oafe-install.log 2>&1

  # Works in 16.04
	if [ ! -d $HOME/.config/autostart ]; then
		sudo -u $SUDO_USER mkdir -p $HOME/.config/autostart
	fi

  # Works in 16.04 too.
	if [ ! -L $HOME/.config/autostart ]; then
		sudo -u $SUDO_USER cp /usr/share/sift/other/gnome-terminal.desktop $HOME/.config/autostart
	fi

  # Works in 16.04 too
	if [ ! -e /usr/share/unity-greeter/logo.png.ubuntu ]; then
		sudo cp /usr/share/unity-greeter/logo.png /usr/share/unity-greeter/logo.png.ubuntu
		sudo cp /usr/share/sift/images/login_logo.png /usr/share/unity-greeter/logo.png
	fi

  # Setup user favorites (only for 12.04)
  sudo -u $SUDO_USER dconf write /desktop/unity/launcher/favorites "['nautilus.desktop', 'gnome-terminal.desktop', 'firefox.desktop', 'gnome-screenshot.desktop', 'gcalctool.desktop', 'bless.desktop', 'autopsy.desktop', 'wireshark.desktop']" >> $HOME/oafe-install.log 2>&1

  # Setup the login background image
  cp /opt/oafe/oafeubuntu/branding/OAFE_Background_1920_1080.jpg /usr/share/backgrounds/warty-final-ubuntu.png

  chown -R $SUDO_USER:$SUDO_USER $HOME
}

configure_virtualbox_vms() {

echoinfo "Downloading and installing Cuckoo Analysis VMs...this could take a while ~7GB"
        if [ ! -d /opt/oafe/VMs ]; then
	      	mkdir -p /opt/oafe/VMs
		chown $SUDO_USER:$SUDO_USER /opt/oafe/VMs
	 	chmod 775 /opt/oafe/VMs
		chmod g+s /opt/oafe/VMs
	fi
        wget https://www.dropbox.com/s/jtcwcytfo7syb3b/Windows7x64VLSandbox1.ova?dl=0 -O /opt/oafe/VMs/Windows7x64VLSandbox1.ova | tee -a "$HOME/oafe-install.log"
        export VBOX_USER_HOME=/opt/oafe/VMs
        vboxmanage hostonlyif create
        vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1
        iptables -A FORWARD -o eth0 -i vboxnet0 -s 192.168.56.0/24 -m conntrack --ctstate NEW -j ACCEPT
        iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A POSTROUTING -t nat -j MASQUERADE
        sysctl -w net.ipv4.ip_forward=1
        sudo -u cfi vboxmanage import /opt/oafe/VMs/Windows7x64VLSandbox1.ova
}

configure_fastincidentresponse_vm() {
    echoinfo "Downloading and importing Fast Incident Response VM"
    wget https://www.dropbox.com/s/mgig4r6bzcgzgbu/FIR-VBox-Template.ova?dl=0 -O /opt/oafe/VMs/FIR-VBox-Template.ova | tee -a "$HOME/oafe-install.log"
    export VBOX_USER_HOME=/opt/oafe/VMs
    sudo -u cfi vboxmanage import /opt/oafe/VMs/FIR-VBox-Template.ova
}

complete_message() {
    echo
    echo "Installation Complete!"
    echo
    echo "Obtain an OpenVPN OAFENET configuration file"
    echo "Copy the OAFE vpn configration file to /etc/openvpn/"
    echo "be sure to rename the .ovpn file to .conf"
    echo
    echo "The Google Rapid Response Installer will need to be run after the reboot."
    echo "It is located at /opt/oafe/grr/install_google_rapid_response.sh"
    echo
    echo "Documentation: http://oafe.readthedocs.org"
    echo
    echo "If you installed FIR you will need to change the IP address and hostname, as well as the config files for FIR to match the IP change"
    echo
}

complete_message_skin() {
    echo
    echo "sudo reboot"
    echo
}

UPGRADE_ONLY=0
CONFIGURE_ONLY=0
SKIN=0
INSTALL=1
YESTOALL=0
DOWNLOAD_VMs=0
DOWNLOAD_FIR=0

OS=$(lsb_release -si)
ARCH=$(uname -m | sed 's/x86_//;s/i[3-6]86/32/')
VER=$(lsb_release -sr)

if [ $OS != "Ubuntu" ]; then
    echo "SIFT is only installable on Ubuntu operating systems at this time."
    exit 1
fi

if [ $ARCH != "64" ]; then
    echo "OAFE is only installable on a 64 bit architecture at this time."
    exit 2
fi

if [ $VER != "16.04" ]; then
    echo "OAFE is only installable on Ubuntu 16.04 at this time."
    exit 3
fi

if [ `whoami` != "root" ]; then
    echoerror "The OAFE Bootstrap script must run as root."
    echoinfo "Preferred Usage: sudo bootstrap.sh (options)"
    echo ""
    exit 3
fi

if [ "$SUDO_USER" = "" ]; then
    echo "The SUDO_USER variable doesn't seem to be set"
    exit 4
fi

#if [ ! "$(__check_apt_lock)" ]; then
#    echo "APT Package Manager appears to be locked. Close all package managers."
#    exit 15
#fi

while getopts ":hvcsiyudt" opt
do
case "${opt}" in
    h ) usage; exit 0 ;;
    v ) echo "$0 -- Version $__ScriptVersion"; exit 0 ;;
    s ) SKIN=1 ;;
    i ) INSTALL=1 ;;
    c ) CONFIGURE_ONLY=1; INSTALL=0; SKIN=0; ;;
    u ) UPGRADE_ONLY=1; ;;
    y ) YESTOALL=1 ;;
    d ) DOWNLOAD_VMs=1 ;;
    t ) DOWNLOAD_FIR=1 ;;
    \?) echo
        echoerror "Option does not exist: $OPTARG"
        usage
        exit 1
        ;;
esac
done

shift $(($OPTIND-1))

if [ "$#" -eq 0 ]; then
    ITYPE="stable"
else
    __check_unparsed_options "$*"
    ITYPE=$1
    shift
fi

if [ "$UPGRADE_ONLY" -eq 1 ]; then
  echoinfo "SIFT Update"
  echoinfo "All other options will be ignored!"
  echoinfo "This could take a few minutes ..."
  echo ""

  export DEBIAN_FRONTEND=noninteractive

  remove_bad_old_deps || echoerror "Removing Old Depedencies Failed"
  install_ubuntu_${VER}_deps $ITYPE || echoerror "Updating Depedencies Failed"
  install_ubuntu_${VER}_packages $ITYPE || echoerror "Updating Packages Failed"
  install_ubuntu_${VER}_pip_packages $ITYPE || echoerror "Updating Python Packages Failed"
  install_perl_modules || echoerror "Updating Perl Packages Failed"
  install_sift_files || echoerror "Installing/Updating SIFT Files Failed"

  echo ""
  echoinfo "SIFT Upgrade Complete"
  exit 0
fi

# Check installation type
if [ "$(echo $ITYPE | egrep '(dev|stable)')x" = "x" ]; then
    echoerror "Installation type \"$ITYPE\" is not known..."
    exit 1
fi

echoinfo "Welcome to the SIFT Bootstrap"
echoinfo "This script will now proceed to configure your system."

if [ "$YESTOALL" -eq 1 ]; then
    echoinfo "You supplied the -y option, this script will not exit for any reason"
fi

echoinfo "OS: $OS"
echoinfo "Arch: $ARCH"
echoinfo "Version: $VER"

if [ "$SKIN" -eq 1 ] && [ "$YESTOALL" -eq 0 ]; then
    echo
    echo "You have chosen to apply the SIFT skin to your ubuntu system."
    echo
    echo "You did not choose to say YES to all, so we are going to exit."
    echo
    echo "Your current user is: $SUDO_USER"
    echo
    echo "Re-run this command with the -y option"
    echo
    exit 10
fi

if [ "$INSTALL" -eq 1 ] && [ "$CONFIGURE_ONLY" -eq 0 ]; then
    export DEBIAN_FRONTEND=noninteractive
    install_ubuntu_${VER}_deps $ITYPE
    install_ubuntu_${VER}_packages $ITYPE
    install_ubuntu_${VER}_pip_packages $ITYPE
    configure_cpan
    install_perl_modules
    install_sift_files
fi

if [ "$DOWNLOAD_VMs" -eq 1 ]; then
    configure_virtualbox_vms
fi

if [ "$DOWNLOAD_FIR" -eq 1 ]; then
    configure_fastincidentresponse_vm
fi

# Configure for SIFT
configure_ubuntu
#We shouldnt update_clamav_signatures so quickly after the initial install, it causes an error because freshclam is locked.
#update_clamav_signatures

# Configure SIFT VM (if selected)
if [ "$SKIN" -eq 1 ]; then
    configure_ubuntu_sift_vm
    configure_ubuntu_${VER}_sift_vm
fi

complete_message

if [ "$SKIN" -eq 1 ]; then
    complete_message_skin
fi

end=$(date +%s.%N)
runtime=$(python -c "print(${end} - ${start})")
echo "Runtime was $runtime" >> $HOME/oafe-install.log
