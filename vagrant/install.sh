#!/bin/bash

vagrant plugin install \
    vagrant-reload \
    vagrant-scp \
    vagrant-vbguest

until vagrant up DNS; do vagrant halt DNS; done
until vagrant up N2;  do vagrant halt N2;  done
until vagrant up S2;  do vagrant halt S2;  done

vagrant halt;
echo -e "\e[32mAll done! \e[0m"
