#!/bin/bash
cd ~

# Required packages
dnf install -y \
    /vagrant/snort3-0.1-1.fc29.x86_64.rpm \
    bridge-utils \
    vim

# export colourful prompt
if [[ -z `cat ~/.bashrc | grep "export PS1="` ]]; then
    echo 'export PS1="\[\e[32m\][\u@\h:\w]$ \[\e[0m\]"' >> ~/.bashrc
fi
