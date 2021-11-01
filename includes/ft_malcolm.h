
# pragma once

# include <ft_err.h>
# include <proginfo.h>

# include <stdbool.h>

# define MINARGNUM 4

err_t   parse_args(int ac, const char* av[], proginfo_t* const info);
err_t 	init_rawsock(proginfo_t* const info, bool extended);

err_t   mandatory_requests(const proginfo_t* const info);

