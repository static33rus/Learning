FROM alpine:3.5

# Maintainer: Evgeny Nechiporuk

RUN apk --update add bash openssh py2-pip wget tcpdump netcat-openbsd
RUN apk add iperf3
RUN pip install scapy
RUN rm -rf /var/cache/apk/*

EXPOSE 22

# Set the default command.
CMD ["/bin/bash"]
