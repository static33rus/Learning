FROM ubuntu:latest

RUN apt-get update
RUN apt-get -y install software-properties-common
RUN add-apt-repository ppa:jonathonf/python-3.6
RUN apt-get update
RUN apt-get -y install python3.6 python3-pip qt5-default python3-ws4py python3-setuptools python3-pyqt5 \
  pyqt5-dev-tools qttools5-dev-tools python3-pyqt5.qtsvg python3-pyqt5.qtwebkit libqt5webkit5-dev \
  python3-pyqt5.qtwebsockets openssh-server locales \
  && pip3 install gns3-gui==2.1.8 \
  && echo "root:root" | chpasswd \
  && mkdir /var/run/sshd \
  && chmod 0755 /var/run/sshd
RUN locale-gen en_US.UTF-8 \
  && update-locale LANG=en_US.UTF-8 \
  && locale-gen
RUN sed -ie 's/#Port 22/Port 22/g' /etc/ssh/sshd_config \
&& sed -ri 's/#HostKey \/etc\/ssh\/ssh_host_key/HostKey \/etc\/ssh\/ssh_host_key/g' /etc/ssh/sshd_config \
&& sed -ir 's/PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config \
&& sed -ir 's/#HostKey \/etc\/ssh\/ssh_host_rsa_key/HostKey \/etc\/ssh\/ssh_host_rsa_key/g' /etc/ssh/sshd_config \
&& sed -ir 's/#HostKey \/etc\/ssh\/ssh_host_dsa_key/HostKey \/etc\/ssh\/ssh_host_dsa_key/g' /etc/ssh/sshd_config \
&& sed -ir 's/#HostKey \/etc\/ssh\/ssh_host_ecdsa_key/HostKey \/etc\/ssh\/ssh_host_ecdsa_key/g' /etc/ssh/sshd_config \
&& sed -ir 's/#HostKey \/etc\/ssh\/ssh_host_ed25519_key/HostKey \/etc\/ssh\/ssh_host_ed25519_key/g' /etc/ssh/sshd_config \
&& sed -ir 's/#X11Forwarding no/X11Forwarding yes/g' /etc/ssh/sshd_config
RUN /usr/bin/ssh-keygen -A \
  && ssh-keygen -t rsa -b 4096 -f  /etc/ssh/ssh_host_key
#RUN /usr/sbin/sshd -D

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
