
# pragma once

# include <ft_err.h>
# include <proginfo.h>

# include <stdbool.h>

# define SIZEOFIP 4
# define SIZEOFMAC ETH_ALEN
# define HARWARE_TYPE 1
# define ARP_REQUEST 1
# define ARP_REPLY 2
# define ETHER_BROADCAST_MAC (uint8_t[SIZEOFMAC]){ 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF }

# define PRINT_MAC(x, endl) (													\
		printf("%x:%x:%x:%x:%x:%x%s",											\
			(x)[0], (x)[1], (x)[2], (x)[3], (x)[4], (x)[5], (endl) ? "\n" : "")	\
	)

# define PRINT_IP(x, endl) (													\
		printf("%x:%x:%x:%x%s",													\
			(x)[0], (x)[1], (x)[2], (x)[3], endl ? "\n" : "")					\
	)

err_t   send_arp_request_to_target(const proginfo_t* const info);
err_t   send_arp_request_to_router(const proginfo_t* const info);
err_t   send_arp_reply_to_target(const proginfo_t* const info);

err_t   spoof_router(const proginfo_t* const info);
err_t   spoof_target(const proginfo_t* const info);
err_t	reset_arp_target(const proginfo_t* const info);
err_t	reset_arp_router(const proginfo_t* const info);
