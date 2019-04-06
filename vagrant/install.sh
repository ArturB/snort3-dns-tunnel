#!/bin/bash

vagrant plugin install \
    vagrant-reload \
    vagrant-scp \
    vagrant-vbguest

until vagrant up IPS1 --provision; do vagrant halt IPS1; done; vagrant halt IPS1; 
until vagrant up IPS2 --provision; do vagrant halt IPS2; done; vagrant halt IPS2; 
until vagrant up SRV1 --provision; do vagrant halt SRV1; done; vagrant halt SRV1; 
until vagrant up SRV2 --provision; do vagrant halt SRV2; done; vagrant halt SRV2; 
until vagrant up MDNS --provision; do vagrant halt MDNS; done; vagrant halt MDNS; 

./config.sh
