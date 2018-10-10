#!/bin/sh
count=0
while [ $count -lt 100 ]
do
(( count++ ))
#inotifywait ждет когда в папке hostfolder создастся файл, после чего выполнится dhclient. И заново в цикле 100 раз
inotifywait -e create /hostfolder
dhclient
done
