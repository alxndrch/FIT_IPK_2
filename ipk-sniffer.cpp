/**
 * @brief Implementace druheho projektu do IPK (sniffer packetu)
 * @file ipk-sniffer.c
 *
 * @author Alexandr Chalupnik <xchalu15@stud.fit.vutbr.cz>
 * @date 17.4 2020
 */

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <getopt.h>
#include <ifaddrs.h>
#include <iostream>
#include <net/if.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <regex.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "ipk-sniffer.h"

using namespace std;

int main(int argc, char** argv){

    Params par = {.interface = nullptr, .port = -1, .num = 1, .tcp = false, .udp = false};

    // zpracovani argumentu
    if(arg_process(argc, argv, par) == ERR)
        return EXIT_FAILURE;

    // vypis aktivnich rozhrani
    if(par.interface == nullptr){
        if(print_interfaces() == ERR)
            return EXIT_FAILURE;

        return EXIT_SUCCESS;
    }

    if(sniff(par) == ERR)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;

}

int arg_process(int argc, char** argv, Params &params){

    int opt = 0;

    struct option long_opt[] = {
        {"tcp",no_argument, nullptr,'t'},
        {"udp",no_argument, nullptr,'u'},
        {0,0,0,0}
    };

    while(1){

        if((opt = getopt_long(argc,argv, ":i:p:tun:", long_opt, nullptr)) == -1)
            break;

        switch(opt){
            case 'i':
                params.interface = optarg;
                break;
            case 'p':
                if(str2int(optarg, params.port) == ERR){
                    cerr << "invalid port" << endl;
                    return ERR;
                }

                if(params.port < 0){
                    cerr << "invalid port" << endl;
                    return ERR;
                }

                break;
            case 't':
                params.tcp = true;
                break;
            case 'u':
                params.udp = true;
                break;
            case 'n':
                if(str2int(optarg, params.num) == ERR){
                    cerr << "invalid number" << endl;
                    return ERR;
                }

                if(params.num < 1){
                    // TODO: muze byt nastaveno 0? vypis 0 paketů
                    cerr << "invalid number" << endl;
                    return ERR;
                }

                break;
            case '?':
                cerr << "invalid argument" << endl;
                return ERR;
        }

    }

    if(optind < argc){
        cerr << "invalid argument" << endl;
        return ERR;
    }

    if(!params.tcp && !params.udp)
        params.tcp = params.udp = true;

    return SUCC;

}

int str2int(char* str, int &num){

    errno = 0;
    char* end;

    num = (int)strtol(str, &end, 10);

    if (((errno == ERANGE  || errno == EINVAL || errno != 0) && num == 0) || *end)
        return ERR;

    return SUCC;

}

int print_interfaces(){

    struct ifaddrs *ifaddr, *ifa;
    int family, address, size;
    std::string print_fam;
    char host[NI_MAXHOST];

    if(getifaddrs(&ifaddr) == -1)
        return ERR;

    cout << "active network interfaces:" << endl;
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr)
            break;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET || family == AF_INET6) {
            size = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
            print_fam = (family == AF_INET) ? "IPv4" : "IPv6";

            if((address = getnameinfo(ifa->ifa_addr, size, host, NI_MAXHOST,NULL, 0, NI_NUMERICHOST))){
                cerr << "error occurred while finding active network interface" << endl;
                return ERR;
            }

            cout << ifa->ifa_name << "\t" << print_fam << "\taddress: " << host << endl;
        }
    }

    freeifaddrs(ifaddr);

    return SUCC;

}

int sniff(Params &params){

    pcap_t* pcap_handle;  //!< packet capture handle
    bpf_program fp{};
    bpf_u_int32 netmask = 0;
    char filter[] = "tcp or udp port 80";

    //otevreni zarizeni pro zachytavani
    if((pcap_handle = pcap_open_live(params.interface,BUFSIZ,1,1000, nullptr)) == nullptr){
        cerr << "Couldn't open device: " << params.interface << endl;
        return ERR;
    }

    // zpracovani a overeni filteru
    if(pcap_compile(pcap_handle, &fp, filter, 0, netmask) == PCAP_ERROR){
        cerr << "Couldn't parse filter: " << filter << endl;
        return ERR;
    }

    // nastaveni filteru
    if(pcap_setfilter(pcap_handle, &fp) == PCAP_ERROR){
        cerr << "Couldn't set filter: " << filter << endl;
        return ERR;
    }

    // zachytavani paketu
    if(pcap_loop(pcap_handle, params.num, process_packet, nullptr) != 0){
        cerr << "error occured while sniffing packet" << endl;
        return ERR;
    }

    // zavreni zarizeni
    pcap_close(pcap_handle);

    return SUCC;
}

void process_packet(u_char* user, const pcap_pkthdr* header, const u_char* packet){
//    //eth_header = (ether_header*) packet;
    for(int i=0;i<header->len;i++) {
        if(isprint(packet[i]))                /* Check if the packet data is printable */
            printf("%c ",packet[i]);          /* Print it */
        else
            printf(" . ");          /* If not print a . */

        if((i%16==0 && i!=0) || i==header->len-1)
            printf("\n");
    }
}