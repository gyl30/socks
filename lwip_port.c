#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

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
