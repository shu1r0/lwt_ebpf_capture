#!/bin/bash

cd ~
git clone https://github.com/shu1r0/ipnet_mininet.git
cd ipnet_mininet/

sudo chmod +x ./ubuntu-dev/scripts/install_pkg.sh
sudo ./ubuntu-dev/scripts/install_pkg.sh
sudo chmod +x ./ubuntu-dev/scripts/install_networkpkg.sh
sudo ./ubuntu-dev/scripts/install_networkpkg.sh
sudo pip install pytest
sudo pip install -r requirements.txt
sudo pip install -e .
