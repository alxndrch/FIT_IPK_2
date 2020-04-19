/**
 * @brief Implementace druheho projektu do IPK (sniffer packetu)
 * @file ipk-sniffer.h
 *
 * @author Alexandr Chalupnik <xchalu15@stud.fit.vutbr.cz>
 * @date 17.4 2020
 */

#ifndef FIT_IPK_2_IPK_SNIFFER_H
#define FIT_IPK_2_IPK_SNIFFER_H

#define SUCC 0
#define ERR -1

/**
 * parametry z priakazove radky
 */
struct Params{
    char* interface;  //!< nazev rozhrani
    int port;  //!< port
    int num;  //!< pocet vypisovanych paketu
    bool tcp; //!< zobrazuje pouze tcp pakety
    bool udp;  //!< zobrazuje pouze udp pakety
};

/**
 * @brief zpracovani argmumentu
 *
 * @param argc pocet argumentu
 * @param argv argumenty
 * @param params parametry pro beh programu
 * @return ERR v pripade chyby, jinak SUCC
 */
int arg_process(int argc, char** argv, Params &params);

/**
 * @brief prevod cisla v retezci na ciselnou hodnotu
 *
 * @param str retezec
 * @param num vysledne cislo
 * @return ERR v pripade chyby, jinak SUCC
 */
int str2int(char* str, int &num);

/**
 * @brief vypis aktivnich sitovych rozhrani
 *
 * @return ERR v pripade chyby jinak SUCC
 */
int print_interfaces();

/**
 * @brief zachytavani paketu
 *
 * @param params parametry pro beh
 * @return ERR v pripade chyby, jinak SUCC
 */
int sniff(Params &params);


/**
 * @brief zpracovani paktu a vypis informaci
 *
 * @param user
 * @param header
 * @param packet paket
 */
void process_packet(u_char* user, const pcap_pkthdr* header, const u_char* packet);

/**
 * @brief nastaveni filteru pro port o protokol
 *
 * @param params parametry
 * @return retezec ve formatu "<protokol> port <cislo portu>"
 */
std::string set_filter_str(Params &params);

#endif //FIT_IPK_2_IPK_SNIFFER_H
