// normal libraries 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>

// network libraries
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> //ethernet and arp frame 
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <netinet/ether.h>

// #include <stddef.h>

// enum PROTOCOLS { TCP, UDP, ARP, ICMP };