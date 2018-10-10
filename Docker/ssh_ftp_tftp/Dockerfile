FROM alpine:latest

# Maintainer: Egor Tizyaev

RUN apk update
RUN apk add bash vsftpd tftp-hpa openssh
RUN apk add nano
RUN apk add openssl

COPY vsftpd.conf /etc/vsftpd.conf
COPY routerkey /.ssh/routerkey

RUN chmod 500 /.ssh/routerkey

# FTP folders
RUN mkdir -p /tmp/ftp/upload
RUN chown -R ftp:ftp /tmp/ftp
RUN chmod 555 /tmp/ftp
RUN chmod 755 /tmp/ftp/upload

# run vsftp server with command "vsftpd"

# TFTP folders
RUN mkdir /tmp/tftp
RUN chown nobody:nobody /tmp/tftp

# run tftp server with command "in.tftpd -L -s -c /tmp/tftp &"
