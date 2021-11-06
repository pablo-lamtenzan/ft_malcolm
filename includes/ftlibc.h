#pragma once

#include <sys/types.h>

void    ft_memcpy(void *dest, const void *src, size_t n);
void*   ft_memset(void *s, int c, size_t n);
int     ft_strncmp(const char *s1, const char *s2, size_t size);
long    ft_strtol(const char *nptr, char **endptr, register int base);
void*   memmaccpy(void* dest, const char* strmac);