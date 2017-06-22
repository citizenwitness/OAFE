#!/bin/bash -
#===============================================================================
# vim: softtabstop=4 shiftwidth=4 expandtab fenc=utf-8 spell spelllang=en cc=81
#===============================================================================
apt-get install -y build-essential wget git python-dev tcpdump python-bson python-setuptools libevent-dev mongodb libxml2-dev libxslt-dev zlib1g-dev redis-server libffi-dev libssl-dev python-virtualenv
easy_install pip
cd /opt/oafe/OAFE/
git clone https://github.com/tomchop/malcom.git malcom
#cd /opt/oafe/oafeubuntu/malcom/
#virtualenv env-malcom
#source env-malcom/bin/activate
cd /opt/oafe/OAFE/
wget http://www.secdev.org/projects/scapy/files/scapy-latest.tar.gz
tar xvzf scapy-latest.tar.gz
cd /opt/oafe/OAFE/scapy-2.1.0/
python setup.py install
cd /opt/oafe/OAFE/malcom/
pip install -r requirements.txt
cd /opt/oafe/OAFE/malcom/Malcom/auxiliary/geoIP/
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
gunzip -d GeoLite2-City.mmdb.gz
mv GeoLite2-City.mmdb GeoIP2-City.mmdb
cd /opt/oafe/OAFE/malcom
cp malcom.conf.example malcom.conf
pip install netifaces python-dateutil pymongo dnspython twisted scapy redis passlib pyOpenSSL lxml requests gevent geoip2 gevent-websocket flask_restful_swagger
echo $PWD
cd /opt/oafe/OAFE/malcom/
./malcom.py -c malcom.conf
