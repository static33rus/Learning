FROM debian

RUN export DEBIAN_FRONTEND=noninteractive

RUN apt update
RUN apt-get install iproute2
RUN apt-get --no-install-recommends install net-tools
RUN apt-get --no-install-recommends install nano
RUN apt-get --no-install-recommends -y install tacacs+
