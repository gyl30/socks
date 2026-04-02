#include <time.h>
#include <stdlib.h>
#ifdef _WIN32
#include <stdio.h>
#include <stdarg.h>
#endif

unsigned int lwip_port_rand(void)
{
    static int seeded = 0;
    if (!seeded)
    {
        seeded = 1;
        srand((unsigned int)time(NULL));
    }

    return (((unsigned int)rand()) << 16U) ^ (unsigned int)rand();
}

#ifdef _WIN32
void lwip_win32_platform_diag(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}
#endif
