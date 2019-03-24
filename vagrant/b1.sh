#!/bin/bash

cd ~

# Snort 3 precompiled rpm
dnf makecache
dnf install -y bridge-utils iptables vim

# export colourful prompt
echo 'export PS1="\[\e[32m\][\u@\h:\w]$ \[\e[0m\]"' >> ~/.bashrc
