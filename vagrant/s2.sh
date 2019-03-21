#!/bin/bash

cd ~

# Snort 3 precompiled rpm
dnf makecache
dnf install -y httpd
systemctl enable httpd.service
systemctl start httpd.service
