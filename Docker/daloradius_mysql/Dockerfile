FROM ubuntu:16.04

MAINTAINER MISHANYA_IZ_RDP

ENV MYSQLTMPROOT root

RUN echo mysql-server mysql-server/root_password password $MYSQLTMPROOT | debconf-set-selections;\
  echo mysql-server mysql-server/root_password_again password $MYSQLTMPROOT | debconf-set-selections;\
  apt-get update && apt-get install -y mysql-server mysql-client libmysqlclient-dev \
  nginx php php-common php-gd php-curl php-mail php-mail-mime php-pear php-db php-mysqlnd \
  freeradius freeradius-mysql freeradius-utils vim iputils-ping telnet ethtool iproute2 lftp cron \
  wget unzip && \
  pear install DB && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.cpan	

ENV RADIUS_DB_PWD radpass
ENV CLIENT_NET "0.0.0.0/0"
ENV CLIENT_SECRET testing123
ENV GATEWAY "default"

RUN wget https://github.com/lirantal/daloradius/archive/master.zip && \
	unzip *.zip && \
	mv daloradius-master /var/www/daloradius && \
 	chown -R www-data:www-data /var/www/daloradius && \
	chmod 644 /var/www/daloradius/library/daloradius.conf.php && \
	rm /etc/nginx/sites-enabled/default

#	cp -R /var/www/daloradius/contrib/chilli/portal2/hotspotlogin /var/www/daloradius

COPY init.sh /
COPY backup.sh /
COPY PPPoE.gz /	
COPY etc/nginx/radius.conf /etc/nginx/sites-enabled/
		

	
EXPOSE 1812:1812/udp 
EXPOSE 1813:1813/udp
EXPOSE 80

ENTRYPOINT ["/init.sh"]