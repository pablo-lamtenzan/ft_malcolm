
# pragma once
# include <stdio.h>

typedef enum	err
{
	SUCCESS,
	INVARG,
	INVSYSCALL,
	INVPACKETLEN,
}				err_t;

# define PRINT_ERROR(x, args...) (dprintf(2, x, args))

#ifndef __progname
# define __progname "ft_malcolm"
#endif

# define MSG_ERROR_SYSCALL __progname ": error: syscall `%s\'failed for some reason" "\n"
# define MSG_ERROR_INVMAC __progname ": invalid mac address: (%s)" "\n"
# define MSG_ERROR_INVIP __progname ": invalid ip address: (%s)" "\n"

# define MSG_USAGE "Usage:\n" \
__progname "<pc_ip> <pc_mac> <target_ip> <target_s mac> [router_ip] [router_mac] [ --sdtout ]\n\
\t-pc_ip: the IP address of the machine having <pc_mac> as MAC address\n\
\t-pc_mac: the MAC address that will be spoofed in computer having <target_mac> MAC adress's ARP table\n\
\t-target_ip: the IP address of the machine which ARP table will be spoofed with <pc_mac>\n\
\t-target_mac: the MAC address of the machine which ARP table will be spoofed with <pc_mac>\n\
\t-router_ip: (Optional) another IP of a targeted machine, works like <target_ip>\n\
\t-router_mac: (Optional) another MAC of a targeted machine, works like <target_mac>\n\
\t-stdout: (Optinal) if <router_ip> and <router_mac> are provided the program logs the all the ip packet's\n\
			sent by <target_mac> and <router_mac> to each other. By default the log is performed into \"mitm_log.txt\",\n\
			this option changes the log destination to STDOUT.\n"
