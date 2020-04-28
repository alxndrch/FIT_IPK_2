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
#include <ctime>
#include <getopt.h>
#include <ifaddrs.h>
#include <iostream>
#include <linux/if_ether.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <new>
#include <pcap/pcap.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
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
    char errbuf[PCAP_ERRBUF_SIZE];  //!< chybovy vystup
    bpf_program fp{};
    bpf_u_int32 netmask = 0;
    string s = set_filter_str(params); //"tcp or udp port 80";

    // prevod string na char*
    char filter[s.size() + 1];
    s.copy(filter, s.size() + 1);
    filter[s.size()] = '\0';

    //otevreni zarizeni pro zachytavani
    if((pcap_handle = pcap_open_live(params.interface,BUFSIZ,1,1000, errbuf)) == nullptr){
        cout << errbuf << endl;
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

    vector<char> hex_dump;  //!< hexadecimalni obsah paketu
    unsigned header_len = 0;  //!< celkova velikost hlavicky

    const tm *p_time = localtime(&header->ts.tv_sec);  //!< cas paketu
    char timestr[16];  //!< cas paketu v retezci

    udphdr *udp_h{};  //!< hlavicka UDP
    tcphdr *tcp_h{};  //!< hlavicka TCP
    iphdr *ip4_h{};  //!< hlavicka IPv4 datagramu
    ip6_hdr *ip6_h{};  //!< hlavicka IPv6 datagramu
    ether_header* eth_h{};  //!< hlavicka ethernetoveho ramce

    u_int16_t dport = 0;  //!< cilovy port
    u_int16_t sport = 0;  //!< zdrojovy port

    char* dest = nullptr;  //!< cilova IP adresa
    char* src = nullptr;  //!< zrojova IP adresa

    hostent *dest_addr = nullptr;  //!< cilova adresa
    hostent *src_addr = nullptr; //!< zrojova adresa

    in_addr_t ip = 0;  //!< pomocna promenna pro vyhodnoceni domenoveho jmena

    strftime(timestr, sizeof(timestr),"%H:%M:%S",p_time);
    printf("%s.%03ld ", timestr, header->ts.tv_usec);

    eth_h = (ether_header*) (packet);

    if(ntohs(eth_h->ether_type) == ETHERTYPE_IPV6){
        ip6_h = (ip6_hdr*) (packet + ETH_HLEN);

        alloc_strs(&src,&dest,40);
        inet_ntop(AF_INET6, &ip6_h->ip6_src, src, 40);
        inet_ntop(AF_INET6, &ip6_h->ip6_dst, dest, 40);

        ip = inet_addr(src);
        src_addr = gethostbyaddr((void*)&ip, 16, AF_INET);
        if(src_addr == nullptr) cout << src;
        else cout << src_addr->h_name;


        if(ip6_h->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP){
            tcp_h = (tcphdr*) (packet + ETH_HLEN + 40);
            sport = ntohs(tcp_h->th_sport);
            dport = ntohs(tcp_h->th_dport);
        }else if(ip6_h->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP){
            udp_h = (udphdr*) (packet + ETH_HLEN + 40);
            sport = ntohs(udp_h->uh_sport);
            dport = ntohs(udp_h->uh_dport);
        }
        cout << " : " << sport << " > ";

        ip = inet_addr(dest);
        dest_addr = gethostbyaddr((void*)&ip, 16, AF_INET);
        if(dest_addr == nullptr) cout << dest;
        else cout << dest_addr->h_name;
        cout << " : " << dport << endl;

        clean_strs(&src,&dest);
        header_len = tcp_h != nullptr? ETH_HLEN + 40 + tcp_h->doff*4 : ETH_HLEN + ip4_h->ihl*4 + 8;

    }else if(ntohs(eth_h->ether_type) == ETHERTYPE_IP){
        ip4_h = (iphdr*) (packet + ETH_HLEN);

        alloc_strs(&src,&dest,16);
        inet_ntop(AF_INET, &ip4_h->saddr, src,16);
        inet_ntop(AF_INET, &ip4_h->daddr, dest,16);

        ip = inet_addr(src);
        src_addr = gethostbyaddr((void*)&ip, 16, AF_INET);
        if(src_addr == nullptr) cout << src;
        else cout << src_addr->h_name;

        if(ip4_h->protocol == IPPROTO_TCP){
            tcp_h = (tcphdr*) (packet + ETH_HLEN + ip4_h->ihl*4);
            sport = ntohs(tcp_h->th_sport);
            dport = ntohs(tcp_h->th_dport);
        }else if(ip4_h->protocol == IPPROTO_UDP){
            udp_h = (udphdr*) (packet + ETH_HLEN + ip4_h->ihl*4);
            sport = ntohs(udp_h->uh_sport);
            dport = ntohs(udp_h->uh_dport);
        }


        ip = inet_addr(dest);
        dest_addr = gethostbyaddr((void*)&ip, 16, AF_INET);

        cout << " : " << sport << " > ";

        if(dest_addr == nullptr) cout << dest;
        else cout << dest_addr->h_name;
        cout << " : " << dport << endl;

        clean_strs(&src,&dest);
        header_len = tcp_h != nullptr? ETH_HLEN + ip4_h->ihl*4 + tcp_h->doff*4 : ETH_HLEN + ip4_h->ihl*4 + 8;
    }

    print_packet(packet, 0, header_len);  // vypis hlavicky
    print_packet(packet, header_len, header->len);  // vypis dat

}

string set_filter_str(Params &params){

    string port = to_string(params.port);
    string protocol;

    if(params.tcp && !params.udp)
        protocol = "tcp";
    else if(!params.tcp && params.udp)
        protocol = "udp";
    else
        protocol = "tcp or udp";

    if(params.port == -1){
        return protocol;
    }

    string filter = protocol + " port " + port;

    return filter;

}

int alloc_strs(char** src, char** dest, int len){

    try{
        *src = new char[len];
    } catch (const bad_alloc& e) {
        cerr << "chyba pri alokaci zdroju" << endl;
        return ERR;
    }

    try{
        *dest = new char[len];
    } catch (const bad_alloc& e) {
        cerr << "chyba pri alokaci zdroju" << endl;
        delete [] *src;
        return ERR;
    }

    return SUCC;

}

void clean_strs(char** src, char** dest){

    delete [] *src;
    delete [] *dest;

}

void print_packet(const u_char* packet, unsigned begin, unsigned end){

    vector<char> hex_dump;  //!< hexadecimalni obsah paketu

    /**
     * @param i poradi zpracovavaneho bytu
     * @param y nastaveni prostredni mezery v hexa vypisu
     * @param w nastaveni prostredni mezery v ascci vypisu
     * @param q vypis poradi 16 bytu (0x000, 0x0010, ...)
     * @param offset posunuti pocitadla bytu na radku 1.radek: 0-15, 2.radek: 16-31
     */
    for(unsigned i = 0, y = 1, w = 0, q = 0, offset = 0; i < end-begin; i++,y++, q++) {

        // vypis poctu bytu
        if(q == 0){
            printf("0x%04x: ",(i+begin));
        }
        // byte paketu v hexa
        printf("%02x ",packet[(i+begin)]);

        if(y == 8 && i != (end-begin-1)){
            cout << " ";
            y = 0;
        }

        hex_dump.push_back(packet[(i+begin)]);

        if((i%((offset+1)*15+offset)==0 && i!=0) || i == (end-begin)-1){

            // zarovnani acii znaku do bloku u posledniho radku
            if(i == (end-begin)-1){
                // kompenzace znaku mezerami

                if(i%16 < 8) cout << " "; // komepenzace prostedni mezery u hexa vypisu
                for(int z = i%16; z != 15; z++){
                    cout << "   "; // za kazdy chybejici znak
                }
                cout << " "; // mezera za hexa vypisem
            }

            // vypis ascii
            w = 0;
            for(char & it : hex_dump){
                if(w++ == 8){ // mezera mezi ascii
                    cout << " ";
                }

                if(isprint(it)) cout << it;
                else cout << "." ;
            }
            q = -1;
            hex_dump.clear();
            cout << endl;
            offset++;
        }
    }

    // konec radku za paketem
    if(end-begin != 0)  // pokud bude mit paket prazdne telo, nevypise se mezera
        cout << endl;
}