#ifndef TUN_DEVICE_WINDOWS_HELPER_H
#define TUN_DEVICE_WINDOWS_HELPER_H

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdint.h>
#include <windows.h>
#include <winsock2.h>
#include <netioapi.h>

#include "wintun.h"

#ifdef __cplusplus

struct tun_device_windows_state
{
    HMODULE module = nullptr;
    WINTUN_ADAPTER_HANDLE adapter = nullptr;
    WINTUN_SESSION_HANDLE session = nullptr;
    WINTUN_CREATE_ADAPTER_FUNC* create_adapter = nullptr;
    WINTUN_CLOSE_ADAPTER_FUNC* close_adapter = nullptr;
    WINTUN_GET_ADAPTER_LUID_FUNC* get_adapter_luid = nullptr;
    WINTUN_START_SESSION_FUNC* start_session = nullptr;
    WINTUN_END_SESSION_FUNC* end_session = nullptr;
    WINTUN_GET_READ_WAIT_EVENT_FUNC* get_read_wait_event = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC* receive_packet = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC* release_receive_packet = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC* allocate_send_packet = nullptr;
    WINTUN_SEND_PACKET_FUNC* send_packet = nullptr;
};

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
