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

    // Print milliseconds with three digits
    printf("%s.%03ld%+03d:%02d\n", timestamp_str, timestamp->tv_usec / 1000, 0, 0);
}

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
    Setup *h_args = (Setup *)args;


    // filter mi uz zabezpecuje aby som dostaval iba packety, ktore su danych tipov
    // takze zistim, aky packet som dostal a ten dany packet vypisem v spravnom tvare

    // tu bude mozno nejaka struktura ether
    // struct pcap_pkthdr header;
    print_out_timestamp(&header->ts);

    // Parse Ethernet header
    // struct ether_header *eth_header_for_ip_arp = (struct ether_header *)packet;
    struct ethhdr *eth_header = (struct ethhdr *)packet;
    
    
    // Convert source MAC address to string format
    char source_mac_str[ETHER_ADDR_LEN * 3];
    snprintf(source_mac_str, sizeof(source_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->h_source[0], eth_header->h_source[1], eth_header->h_source[2],
             eth_header->h_source[3], eth_header->h_source[4], eth_header->h_source[5]);
    
    // Convert destination MAC address to string format
    char dest_mac_str[ETHER_ADDR_LEN * 3];
    snprintf(dest_mac_str, sizeof(dest_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->h_dest[0], eth_header->h_dest[1], eth_header->h_dest[2],
             eth_header->h_dest[3], eth_header->h_dest[4], eth_header->h_dest[5]);

    // Print source and destination MAC addresses
    printf("src MAC: %s\n", source_mac_str);
    printf("dst MAC: %s\n", dest_mac_str);

    // toto je iba skuska na vypisanie nejakych bajtov z packetu
    printf("frame length: %d\n", header->len);

    // buffer for ip adresses
    char buffer[INET_ADDRSTRLEN];

    // Check Ethernet type and process accordingly
    if (ntohs(eth_header->h_proto) == ETH_P_IP) {
        // IPv4 packet
        struct ip *ip_header = (struct ip*)(packet + sizeof(struct ethhdr));  // Skip Ethernet header

        // Print source and destination IP addresses
        printf("src IP: %s\n", inet_ntop(AF_INET, &ip_header->ip_src, buffer, INET_ADDRSTRLEN));
        printf("dst IP: %s\n", inet_ntop(AF_INET, &ip_header->ip_dst, buffer, INET_ADDRSTRLEN));

        // Process based on the IP protocol
        if (ip_header->ip_p == 1) { // ICMP
            struct icmphdr *icmp_hdr = (struct icmphdr*) (packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);
            printf("toto je ICMP\n");
        } else if (ip_header->ip_p == 6) { // TCP
            struct tcphdr* tcp_hdr = (struct tcphdr*) (packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);
            printf("src port: %d\n", ntohs(tcp_hdr->th_sport));
            printf("dst port: %d\n", ntohs(tcp_hdr->th_dport));
            printf("toto je TCP\n");
        } else if (ip_header->ip_p == 17) { // UDP
            struct udphdr *udp_hdr = (struct udphdr*) (packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);
            printf("src port: %d\n", ntohs(udp_hdr->uh_sport));
            printf("dst port: %d\n", ntohs(udp_hdr->uh_dport));
            printf("toto je UDP\n");
        } else if (ip_header->ip_p == 2) { // IGMP
            // Assuming the packet contains IGMP message
            printf("toto je IGMP\n");
        } else if (ip_header->ip_p == 58) { // ICMPv6 (MLD is a part of ICMPv6)
            // Assuming the packet contains MLD message
            printf("toto je MLD\n");
        }
    } else if (ntohs(eth_header->h_proto) == ETHERTYPE_ARP) { // ARP
        struct ether_arp *et_arp = (struct ether_arp*)(packet + sizeof(struct ethhdr));
        
        printf("src IP: %s\n", inet_ntop(AF_INET, &et_arp->arp_spa, buffer, INET_ADDRSTRLEN));
        printf("dst IP: %s\n", inet_ntop(AF_INET, &et_arp->arp_tpa, buffer, INET_ADDRSTRLEN));
    }
    // IPv6
    else if (ntohs(eth_header->h_proto) == ETHERTYPE_IPV6) { // IPv6
        struct ip6_hdr *ip6_header = (struct ip6_hdr*)(packet + sizeof(struct ethhdr));  // Skip Ethernet header

        printf("src IP: %s\n", inet_ntop(AF_INET6, &ip6_header->ip6_src, buffer, INET6_ADDRSTRLEN));
        printf("dst IP: %s\n", inet_ntop(AF_INET6, &ip6_header->ip6_dst, buffer, INET6_ADDRSTRLEN));
        
        // Process based on the next header protocol
        if (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 58) { // ICMP6
            // Assuming the packet contains ICMPv6 message
            printf("toto je ICMPv6\n");
        } else if (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 6) { // TCP
            // Assuming the packet contains TCP segment
            printf("toto je TCPv6\n");
        } else if (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 17) { // UDP
            // Assuming the packet contains UDP datagram
            printf("toto je UDPv6\n");
        }
    }


    // teraz vyprintovat src IP, dst IP, src port and dst port podla toho aky protokol to je cez if else
    
    printf("\n");
    // Print the packet data in the desired format
    for (int i = 0; i < header->len; i++) {
        if (i % 16 == 0) {
            printf("0x%04x: ", i);
        }
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0 || i == header->len - 1) {
            // Print additional spaces to align "dot info" section with previous rows
            int numSpaces = (16 - ((i % 16) + 1)) * 3;
            for (int k = 0; k < numSpaces; k++) {
                printf(" ");
            }
            printf("   ");
            for (int j = i - (i % 16); j <= i; j++) {
                if (j < 0 || j >= header->len) {
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
    printf("\n");

}

// tu bude prebiehat parsovanie argumentov a volanie funkcii z ostatnych suborov
// je to hlavny main
int main(int argc, char *argv[]){

    // struktura na ulozenie argumentov z parsovania
    Setup setup;
    int opt;

    // tato konstanta je zle by som povedal, tuto musim definovat sam
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_interfaces;

    get_all_interfaces(&all_interfaces, errbuf);

    // variables to set up sniffer 
    // toto asi inicializovat default hodnoty premennych v setup strukture
	char *interface = NULL;
	int port = 0;
	int n = 1;
    
    // pristupujem cez nazov prvku z enumu

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
                    // ulozim ju do struktury pre argumenty/settings
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
                // pripad ked je prehodene poradenie argumentov a interface je posledny bez hodnoty
                fprintf(stderr, "Missing interface name: cannot specify different argument without interface and its value(name)\n");
                exit(1);
            }
        } else if ((strcmp(argv[i], "-p") == 0)){
            if(i + 1 < argc){
                if (argument_has_necessary_value(argv[++i])){
                    // ulozim ju do struktury pre argumenty/settings
                    setup.port = atoi(argv[i]);
                    setup.FLAGS[PORT] = true;
                    
                    // tuto mozno checknut ci je port v dobrom rozsahu
                } else {
                    fprintf(stderr, "Missing port value\n");
                    exit(1);
                }
            } else {
                // pripad ked je prehodene poradenie argumentov a interface je posledny bez hodnoty
                fprintf(stderr, "Missing port value at the end of a command\n");
                exit(1);
            }
        } else if ((strcmp(argv[i], "--port-destination") == 0)){
            if(i + 1 < argc){
                if (argument_has_necessary_value(argv[++i])){
                    // ulozim ju do struktury pre argumenty/settings
                    setup.destination_port = atoi(argv[i]);
                    setup.FLAGS[DESTINATION_PORT] = true;
                    
                    // tuto mozno checknut ci je port v dobrom rozsahu
                } else {
                    fprintf(stderr, "Missing destination port value\n");
                    exit(1);
                }
            } else {
                // pripad ked je prehodene poradenie argumentov a interface je posledny bez hodnoty
                fprintf(stderr, "Missing destination port value at the end of a command\n");
                exit(1);
            }
        } else if ((strcmp(argv[i], "--port-source") == 0)){
            if(i + 1 < argc){
                if (argument_has_necessary_value(argv[++i])){
                    // ulozim ju do struktury pre argumenty/settings
                    setup.source_port = atoi(argv[i]);
                    setup.FLAGS[SOURCE_PORT] = true;
                    
                    // tuto mozno checknut ci je port v dobrom rozsahu
                } else {
                    fprintf(stderr, "Missing source port value\n");
                    exit(1);
                }
            } else {
                // pripad ked je prehodene poradenie argumentov a interface je posledny bez hodnoty
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
                    // ulozim ju do struktury pre argumenty/settings
                    setup.n = atoi(argv[i]);
                    setup.FLAGS[NUMBER_OF_PACKETS_TO_DISPLAY] = true;
                    
                    // tuto mozno checknut ci je port v dobrom rozsahu
                } else {
                    fprintf(stderr, "Missing number of packets to display\n");
                    exit(1);
                }
            } else {
                // pripad ked je prehodene poradenie argumentov a interface je posledny bez hodnoty
                fprintf(stderr, "Missing number of packets to display at the end of a command\n");
                exit(1);
            }
        } else {
            // -h pre dalsie spustenie aby vedel ako to pouzit
            fprintf(stderr, "Not supported argument\n");
            exit(1);
        }



    }

    // nastavenie poctu packetov na default verziu
    if(setup.FLAGS[NUMBER_OF_PACKETS_TO_DISPLAY] == false){
        setup.n = 1;
    }

    char filter[MAX_FILTER_LENGTH] = "";
    // built-in premenna pre string filter
    FilterStringCreating(filter, setup);

    printf("%s", filter);


    // Declaring variables to store the network address and netmask obtained from pcap_lookupnet().
    bpf_u_int32 netp;
    bpf_u_int32 maskp;

    // Call pcap_lookupnet() to retrieve the network address and netmask associated with the specified network interface.
    // Arguments:
    // - setup.interface_name: Name of the network interface for which network information is to be retrieved.
    // - &netp: Pointer to store the retrieved network address.
    // - &maskp: Pointer to store the retrieved netmask.
    // - errbuf: Buffer to store any error messages in case of failure.
    int lookup_return_code = pcap_lookupnet(setup.interface_name, &netp, &maskp, errbuf);

    // Check the return code of pcap_lookupnet() for success or failure.
    if (lookup_return_code == -1) {
        // If pcap_lookupnet() returns -1, indicating failure:
        // Print an error message indicating the failure and the error message provided by pcap_lookupnet().
        fprintf(stderr, "[ ERR ] - pcap_lookupnet() - %s\n", errbuf);

        // Free memory allocated by pcap_findalldevs() to prevent memory leaks.
        pcap_freealldevs(all_interfaces);

        // Return 1 to indicate failure to the caller.
        return 1;
    }

    pcap_t *handle;
    // create sniffing session
	if ((handle = pcap_open_live(setup.interface_name, BUFSIZ, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

    // nejake kontrola, neviem ci tu musi byt
    // check link-layer (Ethernet has to be supported)
	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}


    // toto budem pouzivat az neskor, cez compile tam nahram stringovy filter, fp = filter
    struct bpf_program fp;

    int compile_return_code = pcap_compile(handle, &fp, filter, 0, netp);
    if (compile_return_code == -1) {
        fprintf(stderr, "[ ERR ] - pcap_compile() - %s\n", errbuf);
        pcap_freealldevs(all_interfaces);
        return 1;
    }

    int setfilter_return_code = pcap_setfilter(handle, &fp);
    if (setfilter_return_code == -1) {
        fprintf(stderr, "[ ERR ] - pcap_setfilter() - %s\n", errbuf);
        pcap_freealldevs(all_interfaces);
        return 1;
    }

    // tuto miesto NULL dat tu strukturu
    int loop_return_code = pcap_loop(handle, setup.n, packet_handler, (unsigned char *)&setup);
    if (loop_return_code == -1) {
        fprintf(stderr, "[ ERR ] - pcap_loop() - maybe infinity - %s\n", errbuf);
        pcap_freealldevs(all_interfaces);
        return 1;
    }

    // TERAZ BY SOM CHEL VYPISAT CAS NAJPRV TOHO PACKETU

    // toto je uz ten zkompilovany filter
    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(all_interfaces);

    // PCAP FUNKCIE NA SOCKET NIE SU OTESTOVANE, FILTER STRING JE V DOBROM TVARE A MAL BY FUNGOVAT
    // TUTO BUDE NASLEDOVAT PCAP_NEXT ALEBO PCAP_LOOP
    // KDE BUDEM ZAZNAMENAVAT KONKRETNE PACKETY
    // Z TYCH PACKIET MUSIM NEJAKO ZISKAT POTREBNE INFORMACIE 
    // NEJAKE FUNKCIE KTORE TO ESTE AJ VYPISU V POZADOVANOM FORMATE

    // FUNKCIA PCAP_LOOP DO KTOREJ VLOZIM FUNKCIU S PREDNASTAVENYM TVAROM
    // V TEJTO FUNKCII SI MUSIM DEFINOVAT A PRETYPOVAT ZOPAR VECI
    // A POSLAT SETUP STRUKTURU S POLOM BOOLOV - TOTO VSETKO ZABALENE V STRUKTURE, PRETYPOVOVAT, POSLAT, ROZBALIT V TEN FUNKCII TYM, ZE TO PRETYPUJEM NASPAT

    // ERROROVE HLASKY V INOM TVARE

    // musime nejako aj zabezpecit, aby nedoslo k segmentation fault pri nezadani hodnoty poctu packetov, ktore chceme sledovat
    // aj pre ostatne argumenty, a toto zabezpecim cez porovnanie i s argc

    // NIE JE TO UPLNE OTESTOVANE ALE PRIBLIZNE TO FUNGUJE AKO MA
    printf("funguje to dobre\n");

    // ked bude zadane iba -i s hodnotou tiez iba print interfaces
    // print_interfaces(all_interfaces);

}
