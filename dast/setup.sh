#!/usr/bin/env bash

set -e

PY_VERSION="2.7.18"

sudo apt update
sudo apt-get update

if [ ! -d "$HOME/.pyenv" ]; then
    curl https://pyenv.run | bash
fi

if [ ! -d "$HOME/.pyenv/versions/$PY_VERSION" ]; then
    pyenv install $PY_VERSION
fi

pyenv local $PY_VERSION


# ---------------------------------- Cuckoo ---------------------------------- #

sudo apt-get install python python-pip python-dev libffi-dev libssl-dev
sudo apt-get install python-virtualenv python-setuptools

sudo apt-get install libjpeg-dev zlib1g-dev swig
sudo apt-get install libfuzzy-dev ssdeep


# Django-based Web Interface
# sudo apt-get install mongodb

# PostgreSQL as database
sudo apt-get install postgresql libpq-dev

# ForKVM
# qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils python-libvirt

sudo apt-get install swig
# sudo pip install m2crypto==0.24.0

# For remote control
# sudo apt install libguac-client-rdp0 libguac-client-vnc0 libguac-client-ssh0 guacd


# -------------------------------- Volatility -------------------------------- #

# Use version 2 for python2.7
# https://github.com/volatilityfoundation/volatility

# -------------------------------- VirtualBox -------------------------------- #

# Cuckoo supports VirtualBox 4.3, 5.0, 5.1, and 5.2
sudo apt install virtualbox
sudo apt install virtualbox-ext-pack
sudo apt install software-properties-common

# --------------------------------- Firejail --------------------------------- #

if [ ! -d "$HOME/firejail" ]; then
    sudo add-apt-repository ppa:deki/firejail
    sudo apt-get update
    sudo apt-get install firejail firejail-profiles
fi

sudo apt-get install rar


# ---------------------------------- Docker ---------------------------------- #

if [ ! -d "$HOME/docker" ]; then
    sudo apt-get install apt-transport-https ca-certificates curl software-properties-common
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    sudo apt-get update
    sudo apt-get install docker-ce
fi

# ---------------------------------- tcpdump --------------------------------- #

sudo apt-get install tcpdump apparmor-utils
sudo aa-disable /usr/sbin/tcpdump

sudo apt-get install libcap2-bin

# -------------------------------- Init Cuckoo ------------------------------- #

sudo adduser cuckoo
sudo usermod -a -G vboxusers cuckoo
# sudo usermod -a -G libvirtd cuckoo

# python -m pip2 install virtualenv
python -m pip install virtualenv
python -m virtualenv venv
source venv/bin/activate

# pip install -U pip2 setuptools
pip install -U pip setuptools
pip install -U cuckoo


# export CUCKOO_CWD=./.cuckoo
mkdir .cuckoo
cuckoo --cwd .cuckoo

# ---------------------------------- tcpdump --------------------------------- #

sudo groupadd pcap
sudo usermod -a -G pcap cuckoo
sudo chgrp pcap /usr/sbin/tcpdump
# sudo chmod +s /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

getcap /usr/sbin/tcpdump

# --------------------------------- Xenserver -------------------------------- #

pip install XenAPI



# ------------------------------- Cuckoo Config ------------------------------ #

# ---------------------------------- Routing --------------------------------- #