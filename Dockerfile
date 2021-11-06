FROM debian:buster

#RUN echo "deb http://archive.debian.org/debian wheezy main contrib non-free" > /etc/apt/sources.list

RUN apt-get update 
RUN apt-get upgrade -y
RUN apt-get install -y build-essential libc6 gcc make bash valgrind lldb net-tools

RUN mkdir -p /ft_malcolm

COPY Makefile /ft_malcolm/Makefile
COPY srcs /ft_malcolm/srcs
COPY includes /ft_malcolm/includes
COPY entrypoint.sh /ft_malcolm/entrypoint.sh
COPY srcs.mk /ft_malcolm/srcs.mk

RUN chmod +xw /ft_malcolm/entrypoint.sh

WORKDIR /ft_malcolm

ENTRYPOINT [ "/bin/sh", "entrypoint.sh" ]
