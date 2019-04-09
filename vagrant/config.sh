#!/bin/bash

VBoxManage modifyvm IPS1 --nic1 natnetwork --nat-network1 BCYB
VBoxManage modifyvm IPS1 --nic2 intnet --intnet2 INET1
VBoxManage modifyvm IPS1 --nicpromisc1 allow-all
VBoxManage modifyvm IPS1 --nicpromisc2 allow-all

VBoxManage modifyvm SRV1 --nic1 intnet --intnet1 INET1
VBoxManage modifyvm SRV1 --nicpromisc1 allow-all

VBoxManage modifyvm IPS2 --nic1 natnetwork --nat-network1 BCYB
VBoxManage modifyvm IPS2 --nic2 intnet --intnet2 INET2
VBoxManage modifyvm IPS2 --nicpromisc1 allow-all
VBoxManage modifyvm IPS2 --nicpromisc2 allow-all

VBoxManage modifyvm SRV2 --nic1 intnet --intnet1 INET2
VBoxManage modifyvm SRV2 --nicpromisc1 allow-all

VBoxManage modifyvm MDNS --nic1 natnetwork --nat-network1 BCYB
VBoxManage modifyvm MDNS --nicpromisc1 allow-all
