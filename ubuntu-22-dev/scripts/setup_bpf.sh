#!/bin/bash


sudo apt install -y bison flex clang gcc llvm libelf-dev bc libssl-dev tmux trace-cmd cmake libdw-dev gcc-multilib libelf-dev

# update iproute2
sudo apt install -y pkg-config bison flex make gcc
cd /tmp
wget https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/iproute2-5.5.0.tar.gz
tar -xzvf ./iproute2-5.5.0.tar.gz
cd ./iproute2-5.5.0

sudo make && sudo make install

cd ..

## prepare
sudo apt-get install -y cmake g++ git automake libtool libgc-dev bison flex \
libfl-dev libgmp-dev libboost-dev libboost-iostreams-dev \
libboost-graph-dev llvm pkg-config python python-scapy python-ipaddr python-ply python3-pip tcpdump \
build-essential autoconf libtool curl git libpcap-dev gcc-multilib unzip python3-distutils
sudo apt install -y linux-tools-$(uname -r) linux-tools-generic

sudo apt install -y libbpf-dev

# install go
wget "https://go.dev/dl/go1.18.3.linux-amd64.tar.gz"
sudo tar -C /usr/local/ -xzf go1.18.3.linux-amd64.tar.gz 
rm go1.18.3.linux-amd64.tar.gz
echo "export PATH=\$PATH:/usr/local/go/bin" >> /home/vagrant/.bashrc
echo "export GOPATH=\$HOME/go" >> /home/vagrant/.bashrc
echo "export PATH=\$PATH:\$GOPATH/bin" >> /home/vagrant/.bashrc
export PATH=$PATH:/usr/local/go/bin

# install docker
# sudo mkdir -m 0755 -p /etc/apt/keyrings
# curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
# echo \
#   "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
#   $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
# sudo apt-get update -y
# sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

cd /tmp
wget https://github.com/ReFirmLabs/binwalk/archive/master.zip
unzip master.zip
cd binwalk-master && sudo python3 setup.py uninstall && sudo python3 setup.py install

cd /tmp
git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git
cd pahole
mkdir build
cd build
cmake -D__LIB=lib ..
sudo make install
sudo ldconfig

echo
echo "---------- Linux Config ----------"
grep -i CONFIG_BPF /boot/config-$(uname -r)
grep -i CONFIG_XDP_SOCKETS /boot/config-$(uname -r)
echo