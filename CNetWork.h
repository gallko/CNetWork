/**
 * @file:   CNetWork.h
 * @authors: Ruslan
 *
 * Created on 18 мая 2017 г., 10:20
 */

#ifndef __CNETWORK_H__
#define __CNETWORK_H__

#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <string>
#include <linux/if_ether.h>


class CNetWork {
public:
    void updateNetInfo(std::string dev);
    void updateNetInfo();
    uint32_t getSelfIP() const;
    uint8_t *getSelfMac(uint8_t *bufMAC);

protected:
    CNetWork(std::string dev);
    virtual ~CNetWork();

    uint32_t getGWIP() const;
    uint8_t *getGWMac(uint8_t *bufMAC);
    
    uint8_t *getMAC(const in_addr_t &ip, uint8_t *bufMAC);
    uint16_t getVALN() const;

private:
    CNetWork(const CNetWork& orig);

    struct arp_header {
        uint16_t hard_type;
        uint16_t protocol_type;
        uint8_t haddr_size;
        uint8_t addr_size;
        uint16_t opcode;
        uint8_t send_mac[ETH_ALEN];
        uint32_t send_ip;
        uint8_t targ_mac[ETH_ALEN];
        uint32_t targ_ip;
    } __attribute__ ((packed));
    
    static const char *FILE_ROUTE;
    static const uint8_t SIZE_MAC_ADDR;
    static const uint8_t SIZE_IP_ADDR;
    static const uint8_t SIZE_ETH_FRAME;
    static const uint8_t NULL_MAC[ETH_ALEN];
    static struct timeval TIMER;
    
    void updateNetWork();
    in_addr_t ip_ansi_to_inet(char *str);
    uint8_t *get_mac_from_arp_table(const in_addr_t &ip, uint8_t *bufMAC);
    void set_mac_from_arp_table(const in_addr_t &ip, uint8_t *bufMAC);

    uint8_t *arpping(const in_addr_t &ip, uint8_t *bufMAC);

    void startTime();
    uint64_t stopTime();
    
    std::string _nameDev;
    int _indexDev;

    uint8_t _selfMAC[ETH_ALEN];
    uint32_t _selfIP;
    uint32_t _selfMask;
    uint16_t _vlan;
    
    uint32_t _defGWIP;
//    uint8_t _defGWMAC[ETH_ALEN];

//    pthread_rwlock_t _block;
};

#endif /* __CNETWORK_H__ */

