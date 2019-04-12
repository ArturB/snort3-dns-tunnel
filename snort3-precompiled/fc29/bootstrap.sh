#!/bin/bash

cd ~

# Basic tools
dnf install -y \
    git \
    rpmdevtools \
    vim

# export colourful prompt
if [[ -z `cat ~/.bashrc | grep "export PS1="` ]]; then
    echo 'export PS1="\[\e[32m\][\u@\h:\w]$ \[\e[0m\]"' >> ~/.bashrc
fi

# Build Snort 3 RPM package
cp -r /vagrant/rpmbuild ~
rpmbuild -bb rpmbuild/SPECS/snort3.spec

# Install snort
dnf install -y ~/rpmbuild/RPMS/x86_64/snort3-0.1-1.fc29.x86_64.rpm
snort -V

# If all done, send built RPM file to host system
cp ~/rpmbuild/RPMS/x86_64/snort3-0.1-1.fc29.x86_64.rpm /vagrant
chown vagrant:vagrant /vagrant/snort3-0.1-1.fc29.x86_64.rpm

