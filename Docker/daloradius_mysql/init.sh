#!/bin/bash

if [ "$GATEWAY" != "default" ]; then
ip route del default
ip route add default via $GATEWAY
fi
ethtool --offload eth0 tx off sg off tso off
service mysql start


mysql -u root --password=$MYSQLTMPROOT -e \
"CREATE DATABASE radius; GRANT ALL ON radius.* TO radius@localhost IDENTIFIED BY '$RADIUS_DB_PWD'; \
flush privileges;"

mysql -uradius --password=$RADIUS_DB_PWD radius  < /etc/freeradius/sql/mysql/schema.sql
mysql -uradius --password=$RADIUS_DB_PWD radius  < /etc/freeradius/sql/mysql/nas.sql
mysql -uradius --password=$RADIUS_DB_PWD radius  < /var/www/daloradius/contrib/db/mysql-daloradius.sql


sed -i 's/password = "radpass"/password = "'$RADIUS_DB_PWD'"/' /etc/freeradius/sql.conf
sed -i 's/#port = 3306/port = 3306/' /etc/freeradius/sql.conf
sed -i -e 's/$INCLUDE sql.conf/\n$INCLUDE sql.conf/g' /etc/freeradius/radiusd.conf
sed -i -e 's|$INCLUDE sql/mysql/counter.conf|\n$INCLUDE sql/mysql/counter.conf|g' /etc/freeradius/radiusd.conf
sed -i -e 's|authorize {|authorize {\nsql|' /etc/freeradius/sites-available/inner-tunnel
sed -i -e 's|session {|session {\nsql|' /etc/freeradius/sites-available/inner-tunnel 
sed -i -e 's|authorize {|authorize {\nsql|' /etc/freeradius/sites-available/default
sed -i -e 's|session {|session {\nsql|' /etc/freeradius/sites-available/default
sed -i -e 's|accounting {|accounting {\nsql|' /etc/freeradius/sites-available/default

sed -i -e 's|auth_badpass = no|auth_badpass = yes|g' /etc/freeradius/radiusd.conf
sed -i -e 's|auth_goodpass = no|auth_goodpass = yes|g' /etc/freeradius/radiusd.conf
sed -i -e 's|auth = no|auth = yes|g' /etc/freeradius/radiusd.conf

sed -i -e 's|\t#  See "Authentication Logging Queries" in sql.conf\n\t#sql|#See "Authentication Logging Queries" in sql.conf\n\tsql|g' /etc/freeradius/sites-available/inner-tunnel 
sed -i -e 's|\t#  See "Authentication Logging Queries" in sql.conf\n\t#sql|#See "Authentication Logging Queries" in sql.conf\n\tsql|g' /etc/freeradius/sites-available/default

sed -i -e 's|sqltrace = no|sqltrace = yes|g' /etc/freeradius/sql.conf



sed -i -e "s/readclients = yes/nreadclients = yes/" /etc/freeradius/sql.conf
echo -e "\nATTRIBUTE Usage-Limit 3000 string\nATTRIBUTE Rate-Limit 3001 string" >> /etc/freeradius/dictionary
echo VENDOR        RDP        45555 >> /etc/freeradius/dictionary
echo BEGIN-VENDOR RDP >> /etc/freeradius/dictionary
echo ATTRIBUTE    SERVICE_NAME        250    string >> /etc/freeradius/dictionary
echo END-VENDOR    RDP >> /etc/freeradius/dictionary


#================DALORADIUS=========================
sed -i "s/$configValues\['CONFIG_DB_PASS'\] = '';/$configValues\['CONFIG_DB_PASS'\] = '"$RADIUS_DB_PWD"';/" /var/www/daloradius/library/daloradius.conf.php
sed -i "s/$configValues\['CONFIG_DB_USER'\] = 'root';/$configValues\['CONFIG_DB_USER'\] = 'radius';/" /var/www/daloradius/library/daloradius.conf.php

if [ -n "$CLIENT_NET" ]; then
echo "client $CLIENT_NET { 
    	secret          = $CLIENT_SECRET 
    	shortname       = clients 
}" >> /etc/freeradius/clients.conf
fi 

gunzip < /PPPoE.gz | mysql -u radius -pradpass radius
chmod a+x /backup.sh
echo "1 8,19 * * *    root    /backup.sh" >>/etc/crontab
service cron start



#======== DELETE INIT CODE ==
echo "#!/bin/bash
if [ "$GATEWAY" != "default" ]; then
ip route del default
ip route add default via $GATEWAY
fi
ethtool --offload eth0 tx off sg off tso off
service cron start
(while :
do
  mysqld_safe >/dev/null
done) & 
php-fpm7.0 & 
nginx & 
/usr/sbin/freeradius -X" > /init.sh


mkdir /run/php & \
mysqld_safe >/dev/null & \
php-fpm7.0 & \
nginx & \
/usr/sbin/freeradius -X

echo "Inited and STERTED"
