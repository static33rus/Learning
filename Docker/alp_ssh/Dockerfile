FROM alpine:3.6
LABEL maintainer "chudasov.v@rdp.ru"

RUN apk update
RUN apk add wget
RUN apk add openssh

RUN wget ftp://10.210.9.98/public/autotests/ecorouter/time_load_test/routerkey
RUN wget ftp://10.210.9.98/public/autotests/ecorouter/time_load_test/EcoRouterOSwerwerwer.txt
