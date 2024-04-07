#include "ipk-sniffer.h"

enum FLAGS { INTERFACE, TCP, UDP, PORT, DESTINATION_PORT, SOURCE_PORT, ICMP4, ICMP6, ARP, NDP, IGMP, MLD, NUMBER_OF_RESULTS };

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

// tu bude prebiehat parsovanie argumentov a volanie funkcii z ostatnych suborov
// je to hlavny main
int main(int argc, char *argv[]){

    int opt;

    // tato konstanta je zle by som povedal, tuto musim definovat sam
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_interfaces;

    get_all_interfaces(&all_interfaces, errbuf);

    // variables to set up sniffer 
	char *interface = NULL;
	int port = 0;
	int n = 1;
	bool protocols[4] = {false, false, false, false, false, false, false, false, false, false, false, false, false};

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

    if (argc == 3){
        if ((strcmp(argv[1], "-i") == 0) || (strcmp(argv[1], "--interface") == 0)){
            if (argument_has_necessary_value(argv[2])){
                // ulozim ju do struktury pre argumenty/settings
                printf("mam value pre interface\n");
            } else {
                fprintf(stderr, "Wrong argument combination: cannot specify different argument without interface and its value(name)\n");
                exit(1);
            }
        } else {
            fprintf(stderr, "Wrong argument combination: with 2 arguments u can specify only interface and its value(name)\n");
            exit(1);
        }
    }

    // all other combinations of parameters, but
    // ./ipk-sniffer -i and his variants has to have name_of_interface
    // ./ipk-sniffer -port_variants only with tcp and udp

    // for (int i = 1; i < argc; i++){
    //     if ((strcmp(argv[i], "--interface") == 0) || (strcmp(argv[i], "-i") == 0)) { 
    //         // ak je za interface argumentom iny argument = interface bez hodnoty
    //         if ((strcmp(argv[i], "--interface") == 0)){

    //         }
    // }

    // for (int i = 1; i < argc; i++){

    //     if ((strcmp(argv[i], "--interface") == 0) || (strcmp(argv[i], "-i") == 0)) {   
    //         // do something
            
    //     }

    //     // // help message 
    //     // if ((strcmp(argv[i], "-h") == 0 ) || (strcmp(argv[i], "--help") == 0)) {
    //     //     printf("./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port}");
    //     //     printf("{[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n");
    //     //     exit(0);
    //     // }
    //     // // interface 
    //     // else if ((strcmp(argv[i], "-i") == 0) || (strcmp(argv[i], "--interface") == 0)) {
    // }
    // // toto musime nejako inak vymysliet lebo -i alebo --interface nemusi mat specifikovanu hodnotu
    // while((opt = getopt(argc, argv, "i:p")) != -1)
    // {
    //     switch(opt)
    //     {
    //         case 'i':
    //             interface = optarg;
    //             // printf("interface: %s", interface);
    //             if (optarg == NULL){
    //                 print_interfaces(all_interfaces);
    //             } else if (interface_exist(optarg)) {
    //                 interface = optarg;
    //             } else {
    //                 fprintf(stderr, "Interface does not exist\n");
    //                 exit(1);
    //             }
    //             break;
    //         case 'p':
    //             printf("Som v porte!");
    //             break;
    //         default:
    //             printf("a pycu nefunguje to dobre este\n");
    //             exit(1);
    //     }
    // }

    printf("funguje to dobre\n");
    // ked bude zadane iba -i s hodnotou tiez iba print interfaces
    // print_interfaces(all_interfaces);

}
