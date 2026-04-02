#include "tun_device_windows_helper.h"

#ifdef _WIN32

#include <string.h>
#include <iphlpapi.h>

DWORD tun_device_windows_configure_interface(const NET_LUID* luid,
                                             const uint32_t mtu,
                                             const void* ipv4_addr,
                                             const uint8_t ipv4_prefix,
                                             const void* ipv6_addr,
                                             const uint8_t ipv6_prefix)
{
    MIB_IFROW if_row;
    DWORD result;

    memset(&if_row, 0, sizeof(if_row));
    result = ConvertInterfaceLuidToIndex(luid, &if_row.dwIndex);
    if (result != NO_ERROR)
    {
        return result;
    }

    result = GetIfEntry(&if_row);
    if (result != NO_ERROR)
    {
        return result;
    }

    if_row.dwMtu = mtu;
    result = SetIfEntry(&if_row);
    if (result != NO_ERROR)
    {
        return result;
    }

    if (ipv4_addr != NULL)
    {
        MIB_UNICASTIPADDRESS_ROW address_row;

        InitializeUnicastIpAddressEntry(&address_row);
        address_row.InterfaceLuid = *luid;
        address_row.OnLinkPrefixLength = ipv4_prefix;
        address_row.DadState = IpDadStatePreferred;
        address_row.Address.Ipv4.sin_family = AF_INET;
        memcpy(&address_row.Address.Ipv4.sin_addr, ipv4_addr, 4);

        result = CreateUnicastIpAddressEntry(&address_row);
        if (result != ERROR_SUCCESS && result != ERROR_OBJECT_ALREADY_EXISTS)
        {
            return result;
        }
    }

    if (ipv6_addr != NULL)
    {
        MIB_UNICASTIPADDRESS_ROW address_row;

        InitializeUnicastIpAddressEntry(&address_row);
        address_row.InterfaceLuid = *luid;
        address_row.OnLinkPrefixLength = ipv6_prefix;
        address_row.DadState = IpDadStatePreferred;
        address_row.Address.Ipv6.sin6_family = AF_INET6;
        memcpy(&address_row.Address.Ipv6.sin6_addr, ipv6_addr, 16);

        result = CreateUnicastIpAddressEntry(&address_row);
        if (result != ERROR_SUCCESS && result != ERROR_OBJECT_ALREADY_EXISTS)
        {
            return result;
        }
    }

    return ERROR_SUCCESS;
}

#endif
