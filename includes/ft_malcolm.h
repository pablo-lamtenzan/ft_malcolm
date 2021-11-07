
# pragma once

# include <ft_err.h>
# include <proginfo.h>

# include <signal.h>
# include <stdbool.h>

# define MINARGNUM 4

err_t   parse_args(int ac, const char* av[], proginfo_t* const info);
err_t 	init_rawsock(proginfo_t* const info, bool extended);
err_t	printf_ifnic();
err_t   mandatory_requests(const proginfo_t* const info);

err_t   parse_optional_args(const char* av[], proginfo_t* const info, bool* const isstdout);
err_t   man_in_the_middle(const char* av[], const proginfo_t* const info, volatile sig_atomic_t* unpoinson);
void    log_content(uint8_t* const content, ssize_t contentlen, bool isstdout);
void*   getmacfromstr(const char* strmac);