
# pragma once

# include <ft_err.h>
# include <proginfo.h>

# include <stdbool.h>

# define SIZEOFIP 4
# define SIZEOFMAC ETH_ALEN
# define HARWARE_TYPE 1
# define ARP_REQUEST 1
# define ARP_REPLY 2

err_t   send_arp_request_to_target(const proginfo_t* const info, bool multicast);
err_t   send_arp_request_to_router(const proginfo_t* const info, bool multicast);
err_t   send_arp_reply_to_target(const proginfo_t* const info, bool multicast);
err_t   send_arp_request_to_router(const proginfo_t* const info, bool multicast);
err_t	reset_arp_target(const proginfo_t* const info, bool multicast);
err_t	reset_arp_router(const proginfo_t* const info, bool multicast);
