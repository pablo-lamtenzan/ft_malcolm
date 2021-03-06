
# pragma once

# include <netdb.h>

typedef struct		ft_node
{
	const char*		ip;
	const char*		mac;
	struct sockaddr	addr;
}					node_t;

typedef struct	proginfo
{
	node_t		mymachine;
	node_t		target;
	node_t		router;
	int			sockarp;
	int			sockip;
}				proginfo_t;
