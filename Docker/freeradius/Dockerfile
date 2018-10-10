FROM alpine:3.6
LABEL maintainer "mgubanov@ecotelecom.ru"

RUN apk update
RUN apk --no-cache add freeradius==3.0.13-r2 freeradius-radclient
# RUN sed -i '1 i\ecouser Cleartext-Password := "ecopass"' /etc/raddb/users
# RUN sed -i 's/ipaddr = 127.0.0.1/ipaddr = */g' /etc/raddb/clients.conf
