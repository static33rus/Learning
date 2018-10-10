FROM alpine:3.5

# Maintainer: Evgeny Nechiporuk

RUN apk --update add bash openssh py2-pip
RUN apk add iperf3
RUN apk add iproute2
RUN apk add tcpreplay --update-cache --repository http://dl-3.alpinelinux.org/alpine/edge/testing/ --allow-untrusted
RUN pip install scapy
RUN rm -rf /var/cache/apk/*
RUN wget ftp://ftp.rdp.ru/public/autotests/ecorouter/Generator/gen_conf -P /tmp/


EXPOSE 22

# Set the default command.
CMD ["/bin/bash"]
