#include "ipk-sniffer.h"

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
#include <pcap/pcap.h> // Packet capturing library
#include <arpa/inet.h>
#include <netinet/if_ether.h> //ethernet and arp frame 
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netinet/ip.h>


// print the names of the available interfaces
int print_interfaces(pcap_if_t *all_interfaces)
{
	printf("Interfaces:\n");
	
    // pcap_if_t represents information about a network interface
	pcap_if_t *tmp_interfaces;
	for (tmp_interfaces = all_interfaces; tmp_interfaces; tmp_interfaces = tmp_interfaces->next)
	{
		printf("-> %s\n", tmp_interfaces->name);
	}

	exit(0);
}

// load all available interfaces
int get_all_interfaces(pcap_if_t **all_interfaces, char *errbuf)
{
	if (pcap_findalldevs(all_interfaces, errbuf) == -1)
	{
		fprintf(stderr, "Error: Cannot load available interfaces: %s\n", errbuf);
		exit(1);
	}

	return 0;
}

// check if the interface with the given name exists
bool interface_exist(char *int_name){
    pcap_if_t *inter_list;
    char error_message[PCAP_ERRBUF_SIZE];

    // returns 0 on success, PCAP_ERROR on failure 
    if(pcap_findalldevs(&inter_list, error_message) == PCAP_ERROR){
        fprintf(stderr,"Error: Cannot find network interfaces: %s\n",error_message);
        pcap_freealldevs(inter_list);
        return false;
    } 
    
    // get throught all interfaces 
    while (inter_list != NULL){
        // interface find 
        if(strcmp(inter_list->name, int_name) == 0){
            pcap_freealldevs(inter_list);
            return true;
        }  
        inter_list = inter_list->next;
    }

    pcap_freealldevs(inter_list);
    return false;
}

// check if after certain parameters is a necessary value
bool argument_has_necessary_value(char *next_argument){
    if ((strcmp(next_argument, "-i") == 0) ||
        (strcmp(next_argument, "--interface") == 0) ||
        (strcmp(next_argument, "-t") == 0) ||
        (strcmp(next_argument, "--tcp") == 0) ||
        (strcmp(next_argument, "-u") == 0) ||
        (strcmp(next_argument, "--udp") == 0) ||
        (strcmp(next_argument, "-p") == 0) ||
        (strcmp(next_argument, "--port-destination") == 0) ||
        (strcmp(next_argument, "--port-source") == 0) ||
        (strcmp(next_argument, "--icmp4") == 0) ||
        (strcmp(next_argument, "--icmp6") == 0) ||
        (strcmp(next_argument, "--arp") == 0) ||
        (strcmp(next_argument, "--ndp") == 0) ||
        (strcmp(next_argument, "--igmp") == 0) ||
        (strcmp(next_argument, "--mld") == 0) ||
        (strcmp(next_argument, "-n") == 0))
    {
        return false; // if there is another parameter not the expected value, return false
    } else {
        return true;
    }
}

// create raw filter string for pcap functions based on given parameters
void FilterStringCreating(char* filter, Setup setup){

    // ports
    if (setup.FLAGS[PORT] == true){
        snprintf(filter,MAX_FILTER_LENGTH,"port %d and ", setup.port);
    } 
    if (setup.FLAGS[DESTINATION_PORT] == true){
        snprintf(filter,MAX_FILTER_LENGTH,"dst port %d and", setup.destination_port);
    } 
    if (setup.FLAGS[SOURCE_PORT] == true){
        snprintf(filter,MAX_FILTER_LENGTH,"src port %d and", setup.source_port);
    } 

    // tcp, udp
    if(setup.FLAGS[TCP] && !setup.FLAGS[UDP]){
        strcat(filter, "( tcp ) or ");
    } else if (setup.FLAGS[UDP] && !setup.FLAGS[TCP]){
        strcat(filter, "( udp ) or ");
    } else if (setup.FLAGS[TCP] && setup.FLAGS[UDP]){
        strcat(filter, "( tcp or udp ) or ");
    }

    // other protocols
    if(setup.FLAGS[ARP]){
        strcat(filter,"arp or ");
    }
    if(setup.FLAGS[ICMP4]){
        strcat(filter,"icmp or ");
    }
    if(setup.FLAGS[ICMP6]){
        strcat(filter,"icmp6 or ");
    }
    if(setup.FLAGS[IGMP]){
        strcat(filter,"igmp or ");
    }
    if (setup.FLAGS[MLD]) {
        strcat(filter, "ip6 proto 58 or ");
    }
    if (setup.FLAGS[NDP]) {
        strcat(filter, "icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137 or ");
    }

    // delete the ' or ' from the end of the raw filter string
    size_t len = strlen(filter);
    if (len >= 4) {
    filter[len - 4] = '\0';
    }
}

// print out the current timestamp
void print_out_timestamp(const struct timeval *timestamp) {
    struct tm *local_time;
    char timestamp_str[80];
    time_t t;

    t = timestamp->tv_sec;
    local_time = localtime(&t);

    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%dT%H:%M:%S", local_time);

    printf("%s.%03ld%+03d:%02d\n", timestamp_str, timestamp->tv_usec / 1000, 0, 0);
}

// process a packet and print required information about the packet
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){

    // unused, but packet_handler function will not work without it
    Setup *h_args = (Setup *)args;

    print_out_timestamp(&header->ts);

    // parse Ethernet header
    struct ethhdr *eth_header = (struct ethhdr *)packet;
    
    // convert source MAC address to string format
    char source_mac_str[ETHER_ADDR_LEN * 3];
    snprintf(source_mac_str, sizeof(source_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->h_source[0], eth_header->h_source[1], eth_header->h_source[2],
             eth_header->h_source[3], eth_header->h_source[4], eth_header->h_source[5]);
    
    // convert destination MAC address to string format
    char dest_mac_str[ETHER_ADDR_LEN * 3];
    snprintf(dest_mac_str, sizeof(dest_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->h_dest[0], eth_header->h_dest[1], eth_header->h_dest[2],
             eth_header->h_dest[3], eth_header->h_dest[4], eth_header->h_dest[5]);

    // print source and destination MAC addresses
    printf("src MAC: %s\n", source_mac_str);
    printf("dst MAC: %s\n", dest_mac_str);

    // print message length
    printf("frame length: %d bytes\n", header->len);

    // buffer for ip adresses
    char buffer[INET_ADDRSTRLEN];

    // check ethernet layer protocol
    if (ntohs(eth_header->h_proto) == ETH_P_IP) {
        // IPv4 packet, skip ethernet header
        struct ip *ip_header = (struct ip*)(packet + sizeof(struct ethhdr));  

        printf("src IP: %s\n", inet_ntop(AF_INET, &ip_header->ip_src, buffer, INET_ADDRSTRLEN));
        printf("dst IP: %s\n", inet_ntop(AF_INET, &ip_header->ip_dst, buffer, INET_ADDRSTRLEN));

        // check IP protocol
        if (ip_header->ip_p == 6) { // TCP
            struct tcphdr* tcp_hdr = (struct tcphdr*) (packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);
            printf("src port: %d\n", ntohs(tcp_hdr->th_sport));
            printf("dst port: %d\n", ntohs(tcp_hdr->th_dport));
        } else if (ip_header->ip_p == 17) { // UDP
            struct udphdr *udp_hdr = (struct udphdr*) (packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);
            printf("src port: %d\n", ntohs(udp_hdr->uh_sport));
            printf("dst port: %d\n", ntohs(udp_hdr->uh_dport));
        } 

        // if (ip_header->ip_p == 1) { // ICMP
        //     printf("toto je ICMP\n");
        // } else if (ip_header->ip_p == 2) { // IGMP
        //     printf("toto je IGMP\n");
        // } else if (ip_header->ip_p == 58) { // MLD
        //     printf("toto je MLD\n");
        // }

    } else if (ntohs(eth_header->h_proto) == ETHERTYPE_ARP) { // ARP
        struct ether_arp *et_arp = (struct ether_arp*)(packet + sizeof(struct ethhdr));  // skip ethernet header
        
        printf("src IP: %s\n", inet_ntop(AF_INET, &et_arp->arp_spa, buffer, INET_ADDRSTRLEN));
        printf("dst IP: %s\n", inet_ntop(AF_INET, &et_arp->arp_tpa, buffer, INET_ADDRSTRLEN));
    } else if (ntohs(eth_header->h_proto) == ETHERTYPE_IPV6) { // IPv6
        struct ip6_hdr *ip6_header = (struct ip6_hdr*)(packet + sizeof(struct ethhdr));  // skip ethernet header

        printf("src IP: %s\n", inet_ntop(AF_INET6, &ip6_header->ip6_src, buffer, INET6_ADDRSTRLEN));
        printf("dst IP: %s\n", inet_ntop(AF_INET6, &ip6_header->ip6_dst, buffer, INET6_ADDRSTRLEN));
        
        // process based on the next header protocol
        if (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 6) { // TCP
            struct tcphdr* tcp_hdr = (struct tcphdr*) ((uint8_t*)ip6_header + sizeof(struct ip6_hdr));  // Point to TCP header
            printf("src port: %d\n", ntohs(tcp_hdr->th_sport));
            printf("dst port: %d\n", ntohs(tcp_hdr->th_dport));
        } else if (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 17) { // UDP
            struct udphdr *udp_hdr = (struct udphdr*) ((uint8_t*)ip6_header + sizeof(struct ip6_hdr));  // Point to UDP header
            printf("src port: %d\n", ntohs(udp_hdr->uh_sport));
            printf("dst port: %d\n", ntohs(udp_hdr->uh_dport));
        }

        // if (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 58) { // ICMP6
        //     printf("toto je ICMPv6\n");
        // }
    }


    // empty line after packet information    
    printf("\n");

    // print the packet data in the desired format
    for (int i = 0; i < (int)header->len; i++) {
        if (i % 16 == 0) {
            printf("0x%04x: ", i);
        }
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0 || i == (int)header->len - 1) {
            // print additional spaces to align "dot info" section with previous rows
            int numSpaces = (16 - ((i % 16) + 1)) * 3;
            for (int k = 0; k < numSpaces; k++) {
                printf(" ");
            }
            printf("   ");
            for (int j = i - (i % 16); j <= i; j++) {
                if (j < 0 || j >= (int)header->len) {
                    printf(" ");
                } else if (isprint(packet[j])) {
                    printf("%c", packet[j]);
                } else {
                    printf(".");
                }
            }
            printf("\n");
        }
    }

    // empty line after "dot info"
    printf("\n");
}


// main for packet sniffer, argument parsing
int main(int argc, char *argv[]){

    // structure for saving parsed arguments
    Setup setup;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_interfaces;

    get_all_interfaces(&all_interfaces, errbuf);

	// Initialize setup.FLAGS array to false, 0 .. 13
    for (int i = 0; i < ENUM_LEN; i++) {
        setup.FLAGS[i] = false;
    }

    // ./ipk-sniffer
    if (argc == 1){
        print_interfaces(all_interfaces);
        exit(0);
    }

    // ./ipk-sniffer -i or ./ipkt-sniffer --interface
    if (argc == 2){
        if ((strcmp(argv[1], "-i") == 0) || (strcmp(argv[1], "--interface") == 0)){
            print_interfaces(all_interfaces);
            exit(0);
        } else {
            fprintf(stderr, "Wrong argument combination: cannot specify different argument without interface\n");
            exit(1);
        }
    }

    // all other combinations of parameters, but
    // ./ipk-sniffer -i and his variants has to have name_of_interface
    // ./ipk-sniffer -port_variants only with tcp and udp

    for (int i = 1; i < argc; i++){

        if ((strcmp(argv[i], "-i") == 0) || (strcmp(argv[i], "--interface") == 0)){
            if(i + 1 < argc){
                if (argument_has_necessary_value(argv[++i])){
                    setup.interface_name = argv[i];
                    setup.FLAGS[INTERFACE] = true;

                    if (!interface_exist(setup.interface_name)) {
                        fprintf(stderr, "Entered interface does not exist\n");
                        exit(1);
                    }
                } else {
                    fprintf(stderr, "Wrong argument combination: cannot specify different argument without interface and its value(name)\n");
                    exit(1);
                }
            } else {
                // the case when the order of arguments is mixed and the interface is the last without a value
                fprintf(stderr, "Missing interface name: cannot specify different argument without interface and its value(name)\n");
                exit(1);
            }
        } else if ((strcmp(argv[i], "-p") == 0)){
            if(i + 1 < argc){
                if (argument_has_necessary_value(argv[++i])){
                    setup.port = atoi(argv[i]);
                    if (setup.port >= 1 && setup.port <= 65535) { // check if the port is within the suitable range
                        setup.FLAGS[PORT] = true;
                    } else {
                        fprintf(stderr, "Port number must be in the range 1 to 65535.\n");
                        exit(1);
                    }
                } else {
                    fprintf(stderr, "Missing port value\n");
                    exit(1);
                }
            } else {
                // the case when the order of arguments is mixed and the port is the last without a value
                fprintf(stderr, "Missing port value at the end of a command\n");
                exit(1);
            }
        } else if ((strcmp(argv[i], "--port-destination") == 0)){
            if(i + 1 < argc){
                if (argument_has_necessary_value(argv[++i])){
                    setup.destination_port = atoi(argv[i]);
                    if (setup.destination_port >= 1 && setup.destination_port <= 65535) { // check if the destination port is within the suitable range
                        setup.FLAGS[DESTINATION_PORT] = true;
                    } else {
                        fprintf(stderr, "Destination port number must be in the range 1 to 65535.\n");
                        exit(1);
                    }
                } else {
                    fprintf(stderr, "Missing destination port value\n");
                    exit(1);
                }
            } else {
                // the case when the order of arguments is mixed and the destination port is the last without a value
                fprintf(stderr, "Missing destination port value at the end of a command\n");
                exit(1);
            }
        } else if ((strcmp(argv[i], "--port-source") == 0)){
            if(i + 1 < argc){
                if (argument_has_necessary_value(argv[++i])){
                    setup.source_port = atoi(argv[i]);
                    if (setup.source_port >= 1 && setup.source_port <= 65535) { // check if the source port is within the suitable range
                        setup.FLAGS[SOURCE_PORT] = true;
                    } else {
                        fprintf(stderr, "Source port number must be in the range 1 to 65535.\n");
                        exit(1);
                    }
                } else {
                    fprintf(stderr, "Missing source port value\n");
                    exit(1);
                }
            } else {
                // the case when the order of arguments is mixed and the source port is the last without a value
                fprintf(stderr, "Missing source port value at the end of a command\n");
                exit(1);
            }
        } else if ((strcmp(argv[i], "-u") == 0) || (strcmp(argv[i], "--udp") == 0)){
            setup.FLAGS[UDP] = true;
        } else if ((strcmp(argv[i], "-t") == 0) || (strcmp(argv[i], "--tcp") == 0)){
            setup.FLAGS[TCP] = true;
        } else if ((strcmp(argv[i], "--icmp4") == 0)){
            setup.FLAGS[ICMP4] = true;
        } else if ((strcmp(argv[i], "--icmp6") == 0)){
            setup.FLAGS[ICMP6] = true;
        } else if ((strcmp(argv[i], "--arp") == 0)){
            setup.FLAGS[ARP] = true;
        } else if ((strcmp(argv[i], "--ndp") == 0)){
            setup.FLAGS[NDP] = true;
        } else if ((strcmp(argv[i], "--igmp") == 0)){
            setup.FLAGS[IGMP] = true;
        } else if ((strcmp(argv[i], "--mld") == 0)){
            setup.FLAGS[MLD] = true;
        } else if ((strcmp(argv[i], "-n") == 0)){
            if(i + 1 < argc){
                if (argument_has_necessary_value(argv[++i])){
                    setup.n = atoi(argv[i]);
                    setup.FLAGS[NUMBER_OF_PACKETS_TO_DISPLAY] = true;
                } else {
                    fprintf(stderr, "Missing number of packets to display\n");
                    exit(1);
                }
            } else {
                // the case when the order of arguments is mixed and the number of packets to display is the last without a value
                fprintf(stderr, "Missing number of packets to display at the end of a command\n");
                exit(1);
            }
        } else {
            fprintf(stderr, "Not supported argument\n");
            exit(1);
        }
    }

    // set the number of packets to display to default value
    if(setup.FLAGS[NUMBER_OF_PACKETS_TO_DISPLAY] == false){
        setup.n = 1;
    }

    char filter[MAX_FILTER_LENGTH] = "";

    FilterStringCreating(filter, setup);

    // Declaring variables to store the network address and netmask obtained from pcap_lookupnet().
    bpf_u_int32 netp;
    bpf_u_int32 maskp;

    // retrieve the network address and netmask associated with the specified network interface.
    int lookup_return_code = pcap_lookupnet(setup.interface_name, &netp, &maskp, errbuf);
    if (lookup_return_code == -1) {
        fprintf(stderr, "Error: pcap_lookupnet() - %s\n", errbuf);

        // free memory allocated by pcap_findalldevs() to prevent memory leaks.
        pcap_freealldevs(all_interfaces);
        return 1;
    }

    pcap_t *handle;

    // create sniffing session
	if ((handle = pcap_open_live(setup.interface_name, BUFSIZ, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

    // check link-layer (Ethernet has to be supported)
	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

    // variable to store filter string after compilation
    struct bpf_program fp;

    int compile_return_code = pcap_compile(handle, &fp, filter, 0, netp);
    if (compile_return_code == -1) {
        fprintf(stderr, "Error: pcap_compile() - %s\n", errbuf);
        pcap_freealldevs(all_interfaces);
        return 1;
    }

    int setfilter_return_code = pcap_setfilter(handle, &fp);
    if (setfilter_return_code == -1) {
        fprintf(stderr, "Error: pcap_setfilter() - %s\n", errbuf);
        pcap_freealldevs(all_interfaces);
        return 1;
    }

    // loop through number of packets to display, it calls a packet_handler function in every iteration
    int loop_return_code = pcap_loop(handle, setup.n, packet_handler, (unsigned char *)&setup);
    if (loop_return_code == -1) {
        fprintf(stderr, "[ ERR ] - pcap_loop() - maybe infinity - %s\n", errbuf);
        pcap_freealldevs(all_interfaces);
        return 1;
    }

    // free all alocated resources
    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(all_interfaces);
}