#!/bin/bash

cd ~

# Snort 3 precompiled rpm
dnf makecache
dnf install -y /vagrant/snort3-0.1-1.fc29.x86_64.rpm

