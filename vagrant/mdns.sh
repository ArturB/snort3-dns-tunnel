#!/bin/bash
cd ~

apt update

# export colourful prompt
if [[ -z `cat ~/.bashrc | grep "export PS1="` ]]; then
    echo 'export PS1="\[\e[32m\][\u@\h:\w]$ \[\e[0m\]"' >> ~/.bashrc
fi
