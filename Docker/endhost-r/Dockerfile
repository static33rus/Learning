FROM alpine:3.6
LABEL maintainer "mgubanov@ecotelecom.ru"

RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories
RUN apk update
RUN apk --no-cache add openssh vim nano curl tcpreplay tshark
