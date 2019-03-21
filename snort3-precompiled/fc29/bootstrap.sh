#!/bin/bash

cd ~

# Basic tools
dnf makecache
dnf install -y rpmdevtools

# Build Snort 3 RPM package
cp -r /vagrant/rpmbuild ~
rpmbuild -bb rpmbuild/SPECS/snort3.spec

# Install snort
dnf install -y ~/rpmbuild/RPMS/x86_64/snort3-0.1-1.fc29.x86_64.rpm
snort -V

# If all done, send built RPM file to host system
cp ~/rpmbuild/RPMS/x86_64/snort3-0.1-1.fc29.x86_64.rpm /vagrant
chown vagrant:vagrant /vagrant/snort3-0.1-1.fc29.x86_64.rpm

