
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
# define CORRUPTED_BYTE 0X42//( (uint8_t)((uint8_t)4 | ((uint8_t)2 << 4)) )
# define CORRUPTED_MAC (uint8_t[SIZEOFMAC]){ CORRUPTED_BYTE, CORRUPTED_BYTE, CORRUPTED_BYTE, CORRUPTED_BYTE, CORRUPTED_BYTE, CORRUPTED_BYTE }

# define PRINT_MAC(x, endl) (													\
		printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x%s",								\
			(x)[0], (x)[1], (x)[2], (x)[3], (x)[4], (x)[5], (endl) ? "\n" : "")	\
	)

# define PRINT_IP(x, endl) (													\
		printf("%02d:%02d:%02d:%02d%s",											\
			(x)[0], (x)[1], (x)[2], (x)[3], endl ? "\n" : "")					\
	)

err_t   send_arp_request_to_target(const proginfo_t* const info);
err_t   send_arp_reply_to_target(const proginfo_t* const info);

err_t	send_request_before_spoof_router(const proginfo_t *const info); // maybe change name by send_request_target_broadcast
err_t	send_request_before_spoof_target(const proginfo_t *const info);
err_t	send_request_router_unicast(const proginfo_t *const info);
err_t	send_request_target_unicast(const proginfo_t *const info);

err_t   spoof_router(const proginfo_t* const info);
err_t   spoof_target(const proginfo_t* const info);
err_t	reset_arp_target(const proginfo_t* const info);
err_t	reset_arp_router(const proginfo_t* const info);

err_t corrupt_my_mac_in_target(const proginfo_t *const info);
err_t corrupt_my_mac_in_router(const proginfo_t *const info);
