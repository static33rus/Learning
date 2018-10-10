FROM debian:latest
LABEL maintainer "mgubanov@ecotelecom.ru"

RUN apt update && \
    apt install -y ptpd && \
    apt install -y iproute2 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
