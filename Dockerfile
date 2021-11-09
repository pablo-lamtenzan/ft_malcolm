FROM debian:buster

RUN apt-get update 
RUN apt-get upgrade -y
RUN apt-get install -y build-essential libc6 gcc make bash valgrind less net-tools netcat

RUN mkdir -p /ft_malcolm

COPY Makefile /ft_malcolm/Makefile
COPY srcs /ft_malcolm/srcs
COPY includes /ft_malcolm/includes
COPY entrypoint.sh /ft_malcolm/entrypoint.sh
COPY srcs.mk /ft_malcolm/srcs.mk
COPY launchtest.sh /ft_malcolm/launchtest.sh

RUN chmod +xw /ft_malcolm/entrypoint.sh
RUN chmod +x /ft_malcolm/launchtest.sh

WORKDIR /ft_malcolm

ENTRYPOINT [ "/bin/sh", "entrypoint.sh" ]
