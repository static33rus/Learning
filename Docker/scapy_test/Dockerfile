FROM alpine:3.5

# Maintainer: Evgeny Nechiporuk

RUN apk --update add bash openssh py2-pip
RUN apk add iperf
RUN apk add tcpreplay --update-cache --repository http://dl-3.alpinelinux.org/alpine/edge/testing/ --allow-untrusted
RUN pip install scapy
RUN rm -rf /var/cache/apk/*


EXPOSE 22

# Set the default command.
CMD ["/bin/bash"]
