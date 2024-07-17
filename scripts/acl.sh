#!/bin/bash

if [[ $(id -u) -ne 0 ]]; then
    echo "[ERROR] You must run this script as root" >&2
    exit 1
fi

if ! command -v setfacl &> /dev/null; then
    echo "setfacl is not installed. Please install it first."
    echo "sudo apt install acl -y"
    exit 1
fi

if [ "$#" -ne 3 ]; then
    echo "Please provide the required information."

    read -p "Enter the user: " USER
    read -p "Enter the permissions (e.g., rwx): " PERM
    read -p "Enter the file path: " FILE_PATH
else
    USER=$1
    PERM=$2
    FILE_PATH=$3
fi

/usr/bin/setfacl -m u:$USER:$PERM $FILE_PATH

if [ $? -eq 0 ]; then
    echo "Successfully set ACL permissions for user $USER on file $FILE_PATH."
else
    echo "Failed to set ACL permissions."
fi
