#!/bin/sh

ps aux
/usr/sbin/sshd
in.tftpd --verbose --foreground --secure --create --permissive --user ecouser --address 0.0.0.0:69 /home/ecouser &
vsftpd /etc/vsftpd/vsftpd.conf &
ps aux
exec "$@"
