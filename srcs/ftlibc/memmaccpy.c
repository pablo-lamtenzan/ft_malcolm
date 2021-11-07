# include <ftlibc.h>

void* memmaccpy(void* dest, const char* strmac)
{
    u_int8_t* d = (u_int8_t*)dest;
    u_int8_t  s[18] = {0};

    ft_memcpy(s, strmac, (sizeof(s) / sizeof(*s)) - 1);

    s[2] = 0;
    s[5] = 0;
    s[8] = 0;
    s[11] = 0;
    s[14] = 0;

    d[0] = (u_int8_t)ft_strtol(&s[0], 0, 16);
    d[1] = (u_int8_t)ft_strtol(&s[3], 0, 16);
    d[2] = (u_int8_t)ft_strtol(&s[6], 0, 16);
    d[3] = (u_int8_t)ft_strtol(&s[9], 0, 16);
    d[4] = (u_int8_t)ft_strtol(&s[12], 0, 16);
    d[5] = (u_int8_t)ft_strtol(&s[15], 0, 16);

    return dest;
}
