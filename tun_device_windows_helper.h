#ifndef TUN_DEVICE_WINDOWS_HELPER_H
#define TUN_DEVICE_WINDOWS_HELPER_H

#ifdef _WIN32

#include <stdint.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <netioapi.h>
#include <winsock2.h>

#ifdef __cplusplus
extern "C"
{
#endif

    DWORD tun_device_windows_configure_interface(
        const NET_LUID* luid, uint32_t mtu, const void* ipv4_addr, uint8_t ipv4_prefix, const void* ipv6_addr, uint8_t ipv6_prefix);

#ifdef __cplusplus
}
#endif

#endif

#endif
