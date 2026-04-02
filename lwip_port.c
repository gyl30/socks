#include <stdlib.h>
#include <time.h>

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
