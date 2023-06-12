#!/bin/bash


sudo apt update -y
sudo apt upgrade -y


# for Japanese
sudo timedatectl set-timezone Asia/Tokyo
sudo cat << 'EOF' | sudo tee /etc/default/keyboard
# KEYBOARD CONFIGURATION FILE
# Consult the keyboard(5) manual page.
XKBMODEL="pc105"
XKBLAYOUT="jp"
XKBVARIANT=""
XKBOPTIONS=""

BACKSPACE="guess"
EOF