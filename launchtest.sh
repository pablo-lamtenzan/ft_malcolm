#! /bin/sh

IP=`hostname -I`

# TODO: This conditions still not working
if [[ "${IP}" != "127.23.0.3" ]] ; then
    echo "Bad host: must be launch from 127.23.0.3 (current host is ${IP})"
    exit 1
fi

PREFFIX_IP="172.23.0."
PREFFIX_MAC="02:42:ac:17:00:0"

ft_malcolm "${PREFFIX_IP}3" "${PREFFIX_MAC}3" "${PREFFIX_IP}2" "${PREFFIX_MAC}2" "${PREFFIX_IP}4" "${PREFFIX_MAC}4"

exit 0
