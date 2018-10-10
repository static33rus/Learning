FROM alpine:3.6


RUN apk update
RUN apk add dhclient
RUN apk add --no-cache inotify-tools


RUN mkdir hostfolder
COPY script.sh /usr/local/bin
RUN chmod a+x /usr/local/bin/script.sh
ENTRYPOINT ["script.sh"]








