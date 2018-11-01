#!/bin/bash
mysqldump -u radius -pradpass radius | gzip > `date +./PPPoE.sql.%Y_%m_%d.%H:%M.gz`
lftp -c "open 10.210.9.98; set ftp:use-allo false; mput -O /incoming/m.pavlov/DB_pppoe PPPoE*"
rm PPPoE*.gz