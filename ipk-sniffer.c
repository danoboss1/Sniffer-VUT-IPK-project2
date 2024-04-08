#include "ipk-sniffer.h"

// S NEJAKOU KONSTANTOU JE MOZNO PROBLEM 

// dalsi krok je jednotlive vypisovanie a kontrolovanie cez wireshark
// predtym mozno ci naozaj vsetky argumenty funguju tak ako maju a refactor struktur do ipk-sniffer.h
// vytvorenie dalsich suborov

enum FLAGS_ENUM { INTERFACE, TCP, UDP, PORT, DESTINATION_PORT, SOURCE_PORT, ICMP4, ICMP6, ARP, NDP, IGMP, MLD, NUMBER_OF_PACKETS_TO_DISPLAY };

#define ENUM_LEN 13
#define MAX_FILTER_LENGTH 100

// ked berem tieto porty, tak asi iba jeden z nich to by som mohol skontrolovat pri parsovani argumentov
typedef struct{
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

void FilterStringCreating(char* filter, bool* FLAGS, Setup setup){

    if (FLAGS[PORT] == true){
        snprintf(filter,MAX_FILTER_LENGTH,"port %s and ", setup.port);
    } else {
        snprintf(filter,MAX_FILTER_LENGTH," ");
    }

    if (FLAGS[DESTINATION_PORT] == true){
        snprintf(filter,MAX_FILTER_LENGTH,"src port %d and", setup.destination_port);
    } else {
        snprintf(filter,MAX_FILTER_LENGTH," ");
    }

    if (FLAGS[SOURCE_PORT] == true){
        snprintf(filter,MAX_FILTER_LENGTH,"dst port %d and", setup.destination_port);
    } else {
        snprintf(filter,MAX_FILTER_LENGTH," ");
    }

    // strcat pridava string na koniec uz existujuceho stringu 
    // za kazdym tymto das or a na konci zmazes 3 znaky

    if(FLAGS[TCP] && !FLAGS[UDP]){
        strcat(filter, "( tcp ) or");
    } else if (FLAGS[UDP] && !FLAGS[TCP]){
        strcat(filter, "( udp ) or");
    } else if (FLAGS[TCP] && FLAGS[UDP]){
        strcat(filter, "( tcp or udp ) or");
    }

    // vymazat posledne 3 znaky z filter stringu, aby tam nebol ten or
    size_t len = strlen(filter);
    if (len >= 3) {
    filter[len - 3] = '\0';}
};

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
	bool FLAGS[ENUM_LEN] = {false, false, false, false, false, false, false, false, false, false, false, false, false};

    char* filter[MAX_FILTER_LENGTH] = "";
    // built-in premenna pre string filter
    FilterStringCreating(filter, FLAGS, setup);

    // toto budem pouzivat az neskor, cez compile tam nahram stringovy filter
    struct bpf_program filter;

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
                    FLAGS[INTERFACE] = true;

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
                    FLAGS[PORT] = true;
                    
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
                    FLAGS[DESTINATION_PORT] = true;
                    
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
                    FLAGS[SOURCE_PORT] = true;
                    
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
            FLAGS[UDP] = true;
        } else if ((strcmp(argv[i], "-t") == 0) || (strcmp(argv[i], "--tcp") == 0)){
            FLAGS[TCP] = true;
        } else if ((strcmp(argv[i], "--icmp4") == 0)){
            FLAGS[ICMP4] = true;
        } else if ((strcmp(argv[i], "--icmp6") == 0)){
            FLAGS[ICMP6] = true;
        } else if ((strcmp(argv[i], "--arp") == 0)){
            FLAGS[ARP] = true;
        } else if ((strcmp(argv[i], "--ndp") == 0)){
            FLAGS[NDP] = true;
        } else if ((strcmp(argv[i], "--igmp") == 0)){
            FLAGS[IGMP] = true;
        } else if ((strcmp(argv[i], "--mld") == 0)){
            FLAGS[MLD] = true;
        } else if ((strcmp(argv[i], "-n") == 0)){
            if(i + 1 < argc){
                if (argument_has_necessary_value(argv[++i])){
                    // ulozim ju do struktury pre argumenty/settings
                    setup.n = atoi(argv[i]);
                    FLAGS[NUMBER_OF_PACKETS_TO_DISPLAY] = true;
                    
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

    // musime nejako aj zabezpecit, aby nedoslo k segmentation fault pri nezadani hodnoty poctu packetov, ktore chceme sledovat
    // aj pre ostatne argumenty, a toto zabezpecim cez porovnanie i s argc

    // NIE JE TO UPLNE OTESTOVANE ALE PRIBLIZNE TO FUNGUJE AKO MA
    printf("funguje to dobre\n");

    // ked bude zadane iba -i s hodnotou tiez iba print interfaces
    // print_interfaces(all_interfaces);

}
