FROM alpine

RUN apk update
RUN apk add openssh
RUN apk add nano
RUN apk add iputils
RUN apk add iproute2

COPY routerkey /.ssh/routerkey
COPY ER116.txt /tmp/ER116.txt
COPY ER1004.txt /tmp/ER1004.txt
COPY si_if_ip_ER116.txt /tmp/si_if_ip_ER116.txt
COPY si_if_ip_ER1004.txt /tmp/si_if_ip_ER1004.txt
COPY bridges_ER116.txt /tmp/bridges_ER116.txt
COPY bridges_ER1004.txt /tmp/bridges_ER1004.txt

RUN chmod 500 /.ssh/routerkey

