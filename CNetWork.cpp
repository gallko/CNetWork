#include "CNetWork.h"
#include <iostream>
#include <vector>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

// net
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <net/if.h>           // struct ifreq
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/if_arp.h>
#include <net/route.h>
#include <linux/sockios.h>
#include <linux/if_vlan.h>
#include <define.h>
#include <syslog.h>
#include <cstdio>
#include <unistd.h>
#include <sstream>

const char *CNetWork::FILE_ROUTE = "/proc/net/route";
const uint8_t CNetWork::SIZE_MAC_ADDR = ETH_ALEN;
const uint8_t CNetWork::SIZE_IP_ADDR = 4;
const uint8_t CNetWork::SIZE_ETH_FRAME = 42;
const uint8_t CNetWork::NULL_MAC[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
struct timeval CNetWork::TIMER = timeval();

/* PUBLIC **********************************************************************/

void CNetWork::updateNetInfo(std::string dev) {
//    pthread_rwlock_wrlock(&_block);
    _nameDev = dev;
    _selfIP = 0;
    _selfMask = 0;
    _defGWIP = 0;
    _vlan = 0;
    memset(_selfMAC, 0x00, sizeof(_selfMAC));
//    memset(_defGWMAC, 0x00, sizeof(_defGWMAC));
    updateNetWork();
//    pthread_rwlock_unlock(&_block);
}

void CNetWork::updateNetInfo() {
//    pthread_rwlock_wrlock(&_block);
    _selfIP = 0;
    _selfMask = 0;
    _defGWIP = 0;
    _vlan = 0;
    memset(_selfMAC, 0x00, sizeof(_selfMAC));
//    memset(_defGWMAC, 0x00, sizeof(_defGWMAC));
    updateNetWork();
//    pthread_rwlock_unlock(&_block);
}

/* PROTECTED *******************************************************************/

CNetWork::CNetWork(std::string dev) {
    _nameDev = dev;
//    pthread_rwlock_init(&_block, NULL);
    //updateNetInfo(_nameDev);
}

CNetWork::~CNetWork() {
//    pthread_rwlock_destroy(&_block);
}

/* GET *************************************************************************/
uint32_t CNetWork::getSelfIP() const {
    return _selfIP;
}

uint8_t *CNetWork::getSelfMac(uint8_t *bufMAC) {
    if (unlikely(!bufMAC))
        return bufMAC;
//    pthread_rwlock_rdlock(&_block);
    memcpy(bufMAC, _selfMAC, SIZE_MAC_ADDR);
//    pthread_rwlock_unlock(&_block);
    return bufMAC;
}

in_addr_t CNetWork::getGWIP() const {
    return _defGWIP;
}

uint8_t *CNetWork::getGWMac(uint8_t *bufMAC) {
    if (unlikely(!bufMAC))
        return bufMAC;
//    pthread_rwlock_rdlock(&_block);
//    memcpy(bufMAC, _defGWMAC, SIZE_MAC_ADDR);
//    pthread_rwlock_unlock(&_block);
    getMAC(_defGWIP, bufMAC);
    return bufMAC;
}

uint8_t *CNetWork::getMAC(const in_addr_t &ip, uint8_t *bufMAC) {
    if (unlikely(!bufMAC)) return bufMAC;
    memset(bufMAC, 0x00, SIZE_MAC_ADDR);
    if (unlikely(!ip)) return bufMAC;
    if (ip == _selfIP) {
//        pthread_rwlock_rdlock(&_block);
        mempcpy(bufMAC, _selfMAC, SIZE_MAC_ADDR);
//        pthread_rwlock_unlock(&_block);
        return bufMAC;
    }
    // принадлежит ли нашей подсети
    int res;
    if ((ip & _selfMask) == (_selfIP & _selfMask)) {
        //ищем в арп таблице
        res = memcmp(get_mac_from_arp_table(ip, bufMAC), NULL_MAC, SIZE_MAC_ADDR);
        if (res == 0) {
            //засылаем арп запрос
            LOG("send arpping\n");
            arpping(ip, bufMAC);
        }
        return bufMAC;
    }
    else {
        // нет, MAC шлюза по умолчанию
//        pthread_rwlock_rdlock(&_block);
        res = memcmp(get_mac_from_arp_table(_defGWIP, bufMAC), NULL_MAC, SIZE_MAC_ADDR);
        if (res == 0) {
            //засылаем арп запрос
            LOG("send arpping\n");
            arpping(ip, bufMAC);
        }
//        memcpy(bufMAC, _defGWIP, SIZE_MAC_ADDR);
//        pthread_rwlock_unlock(&_block);
        return bufMAC;
    }
}
/* SET *************************************************************************/

/* PRIVATE *********************************************************************/

void CNetWork::updateNetWork() {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct ifreq ifr;
    uint8_t defGWMAC[SIZE_MAC_ADDR];
    
/*retrieve ethernet interface index*/
    strncpy(ifr.ifr_name, _nameDev.c_str(), IFNAMSIZ);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        print_warning("<warning> ioctl() failed to get index device from %s\n", _nameDev.c_str());
        _indexDev = 0;
    }
    else {
        _indexDev = ifr.ifr_ifindex;
        LOGL("Index for device with interface %s is: %d\n", _nameDev.c_str(), _indexDev);
    }
    
// get MAC
    memset((void *)&ifr, 0x00, sizeof (ifreq));
    strncpy(ifr.ifr_name, _nameDev.c_str(), IFNAMSIZ);
    int res = ioctl(fd, SIOCGIFHWADDR, &ifr);    
    if (res < 0) {
        print_warning("<warning> ioctl() failed to get MAC address from %s\n", _nameDev.c_str());
    }
    else {
        memcpy((void *)_selfMAC, (void *)ifr.ifr_hwaddr.sa_data, SIZE_MAC_ADDR);
        LOGL("MAC address for interface %s is %02X:%02X:%02X:%02X:%02X:%02X\n", _nameDev.c_str(),
             _selfMAC[0], _selfMAC[1], _selfMAC[2], _selfMAC[3], _selfMAC[4], _selfMAC[5]);
    }
// get self IP
    memset((void *) &ifr, 0x00, sizeof (ifreq));
    ifr.ifr_addr.sa_family = AF_INET;    
    strncpy(ifr.ifr_name, _nameDev.c_str(), IFNAMSIZ);    
    res = ioctl(fd, SIOCGIFADDR, &ifr);
    if (res < 0) {
        print_warning("<warning> ioctl() failed to get IP address from %s\n", _nameDev.c_str());
    }
    else {
        memcpy((void *) &_selfIP, (void *) ifr.ifr_addr.sa_data, 4);
        _selfIP = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;
        LOGL("IP address for interface %s is: %08X\n", _nameDev.c_str(), (unsigned int) _selfIP);
    }    
// get mask
    memset((void *) &ifr, 0x00, sizeof (ifreq));
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, _nameDev.c_str(), IFNAMSIZ);
    res = ioctl(fd, SIOCGIFNETMASK, &ifr);
    if (res < 0) {
        print_warning("<warning> ioctl() failed to get MASK from  %s\n", _nameDev.c_str());
    }
    else {
        memcpy((void *) &_selfMask, (void *) ifr.ifr_addr.sa_data, 4);
        _selfMask = ((struct sockaddr_in *) &ifr.ifr_netmask)->sin_addr.s_addr;
        LOGL("Mask for interface %s is: %08X\n", _nameDev.c_str(), (unsigned int) _selfMask);
    }
// get VLAN id
    struct vlan_ioctl_args vlan;
    memset((void *) &vlan, 0x00, sizeof (struct vlan_ioctl_args));
    strncpy(vlan.device1, _nameDev.c_str(), IFNAMSIZ);
    vlan.cmd = GET_VLAN_VID_CMD;
    res = ioctl(fd, SIOCGIFVLAN, &vlan);
    if (res < 0) {
        _vlan = 0;
        LOGL("VLAN = %d\n", _vlan);
    }
    else {
        if (vlan.cmd == GET_VLAN_VID_CMD) {
            _vlan = (uint16_t)vlan.u.VID;
            LOGL("VLAN = %d\n", _vlan);
        }
        else
            _vlan = 0;
    }
    close(fd);
    
    // get GW
    FILE *fr = fopen(FILE_ROUTE, "r");
    if (fr) {
        char dev[256], gw[256], flags[256];
        memset(dev, 0x00, 256);
        memset(gw, 0x00, 256);
        memset(flags, 0x00, 256);
        int flag = 0;
        while (fscanf(fr, "%10s %*s %8s %5s %*s %*s %*s %*s %*s %*s %*s", dev, gw, flags) == 3) {
            flag = atoi(flags);
            if (flag & RTF_UP && flag & RTF_GATEWAY && !strcmp(_nameDev.c_str(), dev)) {
                _defGWIP = ip_ansi_to_inet(gw);
            }
        }
        fclose(fr);
        getMAC(_defGWIP, defGWMAC);
        LOGL("IP address default GW for interface %s is: %08X\n", _nameDev.c_str(), (unsigned int) _defGWIP);
        LOGL("MAC address default GW for interface %s is: %02X:%02X:%02X:%02X:%02X:%02X\n",
             _nameDev.c_str(), defGWMAC[0], defGWMAC[1], defGWMAC[2], defGWMAC[3], defGWMAC[4], defGWMAC[5]);
    }
    else {
        print_warning("<warning> Can't open %s.\n", FILE_ROUTE);
    }
}

in_addr_t CNetWork::ip_ansi_to_inet(char *str) {
    int a1, a2, a3, a4;
    sscanf(str, "%02X%02X%02X%02X", &a1, &a2, &a3, &a4);
    return (in_addr_t)((a1 << 24) | (a2 << 16) | (a3 << 8) | a4);
}

uint8_t *CNetWork::get_mac_from_arp_table(const in_addr_t &ip, uint8_t *bufMAC) {
    if (bufMAC == NULL) return bufMAC;
    memset(bufMAC, 0x00, SIZE_MAC_ADDR);
    if (ip == 0x00) return bufMAC;
    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
        print_warning("<warning> Can't open socket for get MAC address from ARP table: %s(%d).\n",
               strerror(errno), errno);
        return bufMAC;
    }    
    struct arpreq arp;
    struct sockaddr_in *sin;
    memset(&arp, 0x00, sizeof (struct arpreq));
    sin = (struct sockaddr_in *) &arp.arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip;    
    strncpy(arp.arp_dev, _nameDev.c_str(), IFNAMSIZ);    
    if (ioctl(sd, SIOCGARP, &arp) < 0) {
        LOGL("ioctl() failed to get ARP: %s(%d).\n", strerror(errno), errno);
        close(sd);
        return bufMAC;
    }
    close(sd);
    if (arp.arp_flags == 0x00)
        return bufMAC;
    memcpy(bufMAC, arp.arp_ha.sa_data, SIZE_MAC_ADDR);
    return bufMAC;
}


void CNetWork::set_mac_from_arp_table(const in_addr_t &ip, uint8_t *bufMAC) {
    if (bufMAC == NULL || ip == 0x00) return;
    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
        print_warning("<warning> Can't open socket for set MAC address from ARP table: %s(%d).\n",
                      strerror(errno), errno);
        return;
    }
    struct arpreq arp;
    struct sockaddr_in *sin;
    memset(&arp, 0x00, sizeof (struct arpreq));
    sin = (struct sockaddr_in *) &arp.arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip;
    strncpy(arp.arp_dev, _nameDev.c_str(), IFNAMSIZ);
    arp.arp_flags = ATF_COM;
    memcpy(arp.arp_ha.sa_data, bufMAC, SIZE_MAC_ADDR);


    if (ioctl(sd, SIOCGARP, &arp) < 0) {
        LOGL("ioctl() failed to get ARP: %s(%d).\n", strerror(errno), errno);
        close(sd);
        return;
    }
    close(sd);
}

uint8_t *CNetWork::arpping(const in_addr_t &ip, uint8_t *bufMAC) {
    if (bufMAC == NULL) return bufMAC;
    memset(bufMAC, 0x00, SIZE_MAC_ADDR);

    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sd < 0) {
        print_warning("<warning> Failed open socket for sender ARP request: %s(%d).\n",
               strerror(errno), errno);
        return bufMAC;
    }
    
    int sent = 0; // number of bytes sent 
    struct sockaddr_ll socket_address;
    void *buffer = malloc(SIZE_ETH_FRAME); /*Buffer for Ethernet Frame*/
    if (!buffer) {
        print_warning("<warning> Can't allocate of memmory for ethernet frame: %s(%d).\n",
               strerror(errno), errno);
        return bufMAC;
    }
    memset(buffer, 0x00, SIZE_ETH_FRAME);

//    pthread_rwlock_rdlock(&_block);
/*prepare sockaddr_ll*/
    socket_address.sll_family = PF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = _indexDev;
    socket_address.sll_hatype = ARPHRD_ETHER;
    socket_address.sll_pkttype = PACKET_OTHERHOST;
    socket_address.sll_halen = 0;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;


/* prepare ethernet freame*/    
    struct ethhdr *eh = (struct ethhdr *)buffer;
    struct arp_header *ah = (struct arp_header *) ((uint8_t *)buffer + ETH_HLEN);
/* prepare ethernet header*/
    memset(eh->h_dest, 0xFF, SIZE_MAC_ADDR);
    memcpy(eh->h_source, &_selfMAC, SIZE_MAC_ADDR);
    eh->h_proto = htons(ETH_P_ARP);
/* prepare arp header*/
    ah->hard_type = htons(ARPHRD_ETHER); // ethernet
    ah->protocol_type = htons(ETH_P_IP); // ipv4
    ah->haddr_size = SIZE_MAC_ADDR;
    ah->addr_size = SIZE_IP_ADDR;
    ah->opcode = htons(ARPOP_REQUEST);
    memcpy(ah->send_mac, _selfMAC, SIZE_MAC_ADDR);
    ah->send_ip = _selfIP;
    memset(ah->targ_mac, 0x00, SIZE_MAC_ADDR);
    ah->targ_ip = ip;
//    pthread_rwlock_unlock(&_block);

    sent = sendto(sd, buffer, SIZE_ETH_FRAME, 0, (struct sockaddr*) &socket_address, sizeof (socket_address));
    if (sent != SIZE_ETH_FRAME) {
        print_warning("<warning> Failed to send ARP request. Total sent %d bytes, expected %d: %s(%d).\n",
               sent, SIZE_ETH_FRAME, strerror(errno), errno);
        free(buffer); // A total of 50 bytes have been sent, expected
        close(sd);
        return bufMAC;
    }
/* end send ********************************************************************/  
/* start recv ******************************************************************/
    memset(buffer, 0x00, SIZE_ETH_FRAME);
    int len_recv;// = recvfrom(sd, buffer, 0, NULL, NULL);    
    struct timeval tv;
    
    tv.tv_sec = 0;
    tv.tv_usec = 1000000;
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof (struct timeval));
    startTime();
    while (1) {
        len_recv = recv(sd, buffer, SIZE_ETH_FRAME, 0);
        if (len_recv <= 0) {
            LOGL("Socket timeout (%d us)\n", (int)tv.tv_usec);
            break;
        }        
        if(ntohs(eh->h_proto) == ETH_P_ARP &&           // это ARP пакет
                ntohs(ah->opcode) == ARPOP_REPLY &&     // это ответ на ARP запрос
                ah->send_ip == ip) {                    // это ответ на запрошенный IP
            memcpy(bufMAC, ah->send_mac, SIZE_MAC_ADDR);
            break;
        }        
        if (stopTime() > (unsigned int)tv.tv_usec) {
            LOGERR("Long wait ARP answer (%d us)\n", (int)tv.tv_usec);
            return bufMAC;
        }        
    }
/* end recv ********************************************************************/
    
    free(buffer);
    close(sd);

    int res = memcmp(bufMAC, NULL_MAC, SIZE_MAC_ADDR);
    if (res == 0) {
        print_warning("Not found MAC addres for IP 0x%08x\n", ip);
        return bufMAC;
    }
    set_mac_from_arp_table(ip, bufMAC);
    return bufMAC;
}

void CNetWork::startTime() {
    gettimeofday(&TIMER, NULL);
}

uint64_t CNetWork::stopTime() {
    struct timeval old;
    gettimeofday(&old, NULL);
    return (uint64_t)((uint64_t) old.tv_sec * 1000000 + (uint64_t) old.tv_usec) -
            ((uint64_t) TIMER.tv_sec * 1000000 + (uint64_t) TIMER.tv_usec);
}

uint16_t CNetWork::getVALN() const {
    return _vlan;
}

