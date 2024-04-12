#ifndef IPK_SNIFFER
#define IPK_SNIFFER

#include <stdbool.h>


#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

#define ENUM_LEN 13
#define MAX_FILTER_LENGTH 100


enum FLAGS_ENUM { INTERFACE, TCP, UDP, PORT, DESTINATION_PORT, SOURCE_PORT, ICMP4, ICMP6, ARP, NDP, IGMP, MLD, NUMBER_OF_PACKETS_TO_DISPLAY };

typedef struct{
    bool FLAGS[ENUM_LEN];
    char* interface_name;
    int port;
    int destination_port;
    int source_port;
    int n; // number of packet that will be shown
} Setup;


#endif