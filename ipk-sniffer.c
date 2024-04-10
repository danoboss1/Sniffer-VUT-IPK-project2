#include "ipk-sniffer.h"

// S NEJAKOU KONSTANTOU JE MOZNO PROBLEM 

// dalsi krok je jednotlive vypisovanie a kontrolovanie cez wireshark
// predtym mozno ci naozaj vsetky argumenty funguju tak ako maju a refactor struktur do ipk-sniffer.h
// vytvorenie dalsich suborov

// n znamena dlzka, kolkokrat to spustim, to zadavam az ked to budem vyhladavat

enum FLAGS_ENUM { INTERFACE, TCP, UDP, PORT, DESTINATION_PORT, SOURCE_PORT, ICMP4, ICMP6, ARP, NDP, IGMP, MLD, NUMBER_OF_PACKETS_TO_DISPLAY };

#define ENUM_LEN 13
#define MAX_FILTER_LENGTH 100

// ked berem tieto porty, tak asi iba jeden z nich to by som mohol skontrolovat pri parsovani argumentov
typedef struct{
    bool FLAGS[ENUM_LEN];
    char* interface_name;
    int port;
    int destination_port;
    int source_port;
    int n;               // number of packet that will be shown
} Setup;

// pcap_if_t represents information about a network interface
int print_interfaces(pcap_if_t *all_interfaces)
{
	printf("Interfaces:\n");
	
	pcap_if_t *tmp;
	for (tmp = all_interfaces; tmp; tmp = tmp->next)
	{
		printf("-> %s\n", tmp->name);
	}

	exit(0);
}

int get_all_interfaces(pcap_if_t **all_interfaces, char *errbuf)
{
	if (pcap_findalldevs(all_interfaces, errbuf) == -1)
	{
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	return 0;
}

bool interface_exist(char *int_name){
    pcap_if_t *inter_list;
    char error_message[PCAP_ERRBUF_SIZE];

    // returns 0 on succes PCAP_ERROR on failure 
    if(pcap_findalldevs(&inter_list, error_message) == PCAP_ERROR){
        fprintf(stderr,"%s",error_message);
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
        return false;
    } else {
        return true;
    }
}

void FilterStringCreating(char* filter, Setup setup){

    if (setup.FLAGS[PORT] == true){
        snprintf(filter,MAX_FILTER_LENGTH,"port %d and ", setup.port);
    } 

    if (setup.FLAGS[DESTINATION_PORT] == true){
        snprintf(filter,MAX_FILTER_LENGTH,"src port %d and", setup.destination_port);
    } 

    if (setup.FLAGS[SOURCE_PORT] == true){
        snprintf(filter,MAX_FILTER_LENGTH,"dst port %d and", setup.destination_port);
    } 

    // strcat pridava string na koniec uz existujuceho stringu 
    // za kazdym tymto das or a na konci zmazes 3 znaky

    if(setup.FLAGS[TCP] && !setup.FLAGS[UDP]){
        strcat(filter, "( tcp ) or ");
    } else if (setup.FLAGS[UDP] && !setup.FLAGS[TCP]){
        strcat(filter, "( udp ) or ");
    } else if (setup.FLAGS[TCP] && setup.FLAGS[UDP]){
        strcat(filter, "( tcp or udp ) or ");
    }

    if(setup.FLAGS[ARP]){
        strcat(filter,"arp or ");
    }
    if(setup.FLAGS[ICMP4]){
        strcat(filter,"icmp4 or ");
    }
    if(setup.FLAGS[ICMP6]){
        strcat(filter,"icmp6 or ");
    }
    if(setup.FLAGS[IGMP]){
        strcat(filter,"igmp or ");
    }
    if(setup.FLAGS[MLD]){
        strcat(filter,"mld or ");
    }

    // vymazat posledne 3 znaky z filter stringu, aby tam nebol ten or
    size_t len = strlen(filter);
    if (len >= 4) {
    filter[len - 4] = '\0';
    }
}

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
    Setup *h_args = (Setup *)args;

    // toto vypisuje viac ako jeden packet ked nie je zadane cislo

    // toto je iba skuska na vypisanie nejakych bajtov z packetu
    printf("Packet captured, length: %d\n", header->len);
    
    // Print the first 20 bytes of the packet (change this as needed)
    for (int i = 0; i < 20 && i < header->len; i++) {
        printf("%02x ", packet[i]);
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
