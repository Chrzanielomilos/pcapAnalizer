/*
 * decoder.h - dekodowanie nagłówków warstw 2-4 (Ethernet/VLAN, Linux SLL,
 * loopback, raw IP; IPv4, IPv6; TCP, UDP).
 */
#ifndef PA_DECODER_H
#define PA_DECODER_H

#include "common.h"

/* Wynik dekodowania. */
enum {
    DEC_OK = 0,           /* nagłówki zdekodowane poprawnie                 */
    DEC_NOT_IP,           /* ramka bez IP (ARP, LLDP, STP ...)              */
    DEC_TRUNCATED,        /* brak części nagłówka (zbyt mały snaplen)       */
    DEC_MALFORMED,        /* niespójne pola nagłówka                        */
    DEC_UNSUPPORTED_LINK  /* nieobsługiwany typ łącza                       */
};

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

/* Zdekodowany pakiet. Wskaźnik payload odnosi się do bufora libpcap
 * i jest ważny tylko podczas przetwarzania danego pakietu. */
typedef struct {
    double   ts;             /* znacznik czasu [s]                          */
    uint32_t caplen;         /* liczba zapisanych bajtów                    */
    uint32_t wirelen;        /* długość ramki w sieci                       */
    int      status;         /* DEC_*                                       */
    uint16_t ethertype;
    int      vlan_tags;      /* liczba znaczników 802.1Q/802.1ad            */
    uint16_t vlan_id;        /* identyfikator zewnętrznej sieci VLAN        */

    int       ipver;         /* 0, 4 lub 6                                  */
    ip_addr_t src, dst;
    uint8_t   proto;         /* protokół warstwy 4 (numer IANA)            */
    uint8_t   ttl;           /* TTL / hop limit                             */
    uint32_t  ip_total_len;  /* długość datagramu IP                        */
    int       frag;          /* datagram jest fragmentem                    */
    int       ip_cksum_bad;  /* błędna suma kontrolna nagłówka IPv4         */
    int       snap_truncated;/* datagram obcięty przez snaplen              */

    int      l4_valid;       /* nagłówek TCP/UDP zdekodowany                */
    uint16_t sport, dport;
    uint8_t  tcp_flags;
    uint32_t seq, ack;
    uint16_t win;
    uint16_t mss;            /* opcja MSS (0 = brak)                        */
    int      wscale;         /* opcja Window Scale (-1 = brak)              */
    int      sack_perm;
    uint32_t l4_payload_len; /* długość danych L4 wg nagłówków IP/UDP/TCP   */
    const uint8_t *payload;  /* dane L4 (zapisana część)                    */
    uint32_t payload_cap;    /* liczba zapisanych bajtów danych L4          */
} pkt_t;

int decode_packet(int dlt, double ts, uint32_t caplen, uint32_t wirelen,
                  const uint8_t *data, pkt_t *p);

#endif
