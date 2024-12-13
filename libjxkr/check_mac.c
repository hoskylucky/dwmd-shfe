#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>

#include "util/compare_string.h"

/**
 * @brief check if there is a matched mac on the host
 *
 * @param mac
 * @return int  0 for success, -1 for failed
 */
int check_mac(const char *mac)
{
    int ret = -1;
    struct ifreq ifr;
    int sock;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        return -1;
    }

    struct ifaddrs *addresses;
    if (getifaddrs(&addresses) == -1)
    {
        return -1;
    }

    char nmac[20];
    struct ifaddrs *address = addresses;
    while (address)
    {
        // printf("mac %s\n", address->ifa_name);
        if (address->ifa_addr)
        {
            int family = address->ifa_addr->sa_family;
            if (family == AF_INET)
            {
                if (string_nocase_compare((char *)"lo", address->ifa_name) != 0)
                {
                    strcpy(ifr.ifr_name, address->ifa_name);
                    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
                    {
                        unsigned char *hwaddr = (unsigned char *)ifr.ifr_hwaddr.sa_data;
                        snprintf(nmac, sizeof(nmac), "%02X:%02X:%02X:%02X:%02X:%02X", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
                        if (string_nocase_compare(nmac, (char *)mac) == 0)
                        {
                            ret = 0;
                            break;
                        }
                    }
                }
            }
        }

        address = address->ifa_next;
    }
    freeifaddrs(addresses);
    close(sock);
    return ret;
}