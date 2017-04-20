#!/bin/bash -
#===============================================================================
# vim: softtabstop=4 shiftwidth=4 expandtab fenc=utf-8 spell spelllang=en cc=81
#===============================================================================
##This script enables the ubuntu firewall and then adds the required rules for all the services we run
ufw enable
ufw allow 8501
ufw allow 8504
ufw allow 8506
ufw allow 8502
ufw allow 8507
ufw allow 9000
ufw allow 8505
ufw allow 8503
ufw allow 8509
ufw allow 5900
ufw allow 5901
ufw allow 22
ufw allow 8006
ufw allow 8005
ufw allow 32505
ufw deny out to any port 9001
ufw deny 110
ufw status
