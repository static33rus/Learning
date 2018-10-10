#Указываем ОС
FROM alpine:3.6
# Устанавливаем ктилиты
RUN apk update
RUN apk add dhclient
RUN apk add at

#Создаем скрипт, который запустит dhclient и создаст файл bugaga
RUN echo '#!/bin/bash' >> hz.sh
RUN echo 'dhclient' >> hz.sh
RUN echo 'touch bugaga' >> hz.sh

#Делаем исполняемым
RUN chmod a+x hz.sh

#Копируем скрипт из текущей папки в /usr/local/bin
COPY script.sh /usr/local/bin

#Делаем исполняемым
RUN chmod a+x /usr/local/bin/script.sh

#Запускаем script.sh во время запуска контейнеров
ENTRYPOINT ["script.sh"]


