FROM alpine:3.5
RUN apk update
RUN apk add bash vsftpd tftp-hpa openssh

RUN adduser -D ecouser && \
    echo -e "ecopass\necopass\n" | passwd ecouser

RUN ssh-keygen -f /etc/ssh/ssh_host_rsa_key -N '' -t rsa && \
    ssh-keygen -f /etc/ssh/ssh_host_dsa_key -N '' -t dsa

RUN mkdir -p /var/lib/ftp && \
    chmod a+rx /var/lib/ftp

COPY vsftpd.conf /etc/vsftpd/vsftpd.conf

COPY docker-entrypoint.sh /usr/local/bin

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["/bin/bash"]
