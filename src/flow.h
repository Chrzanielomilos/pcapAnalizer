/*
 * flow.h - rekonstrukcja dwukierunkowych przepływów TCP/UDP oraz
 * śledzenie stanu i jakości połączeń TCP.
 */
#ifndef PA_FLOW_H
#define PA_FLOW_H

#include "decoder.h"

/* Klucz kanoniczny: punkt końcowy "a" jest mniejszy (adres, port) od "b",
 * dzięki czemu oba kierunki komunikacji trafiają do tego samego przepływu. */
typedef struct {
    ip_addr_t a, b;
    uint16_t  pa, pb;
    uint8_t   proto;
    uint8_t   pad;      /* zawsze 0 - klucz jest haszowany bajt po bajcie */
} flow_key_t;

/* Klasyfikacja przepływu po zakończeniu analizy. */
typedef enum {
    FC_COMPLETE = 0,  /* uzgodnienie + zamknięcie FIN w obu kierunkach     */
    FC_RESET,         /* uzgodnienie + zakończenie RST                     */
    FC_OPEN,          /* uzgodnienie, brak zamknięcia do końca zapisu      */
    FC_HALF_OPEN,     /* SYN -> SYN-ACK, brak końcowego ACK                */
    FC_REJECTED,      /* SYN -> RST (port zamknięty)                       */
    FC_UNANSWERED,    /* SYN bez odpowiedzi                                */
    FC_MIDSTREAM,     /* połączenie rozpoczęte przed początkiem zapisu     */
    FC_UDP_BIDIR,     /* UDP, ruch w obu kierunkach                        */
    FC_UDP_UNIDIR,    /* UDP, ruch tylko od inicjatora                     */
    FC_COUNT
} flow_class_t;

/* Zdarzenia zwracane przez flow_update() (maska bitowa). */
enum {
    EV_RETRANS = 1,
    EV_OOO     = 2,
    EV_DUPACK  = 4,
    EV_ZEROWIN = 8,
    EV_GAP     = 16
};

/* Indeks kierunku: 0 = od inicjatora (klienta), 1 = od odpowiadającego. */
typedef struct flow {
    struct flow *hnext;          /* łańcuch w tablicy mieszającej           */
    flow_key_t key;
    uint32_t id;
    uint8_t  init;               /* 0: inicjatorem jest key.a, 1: key.b     */
    uint8_t  midstream;
    uint8_t  saw_syn, saw_synack, saw_hs_ack, saw_rst, rst_dir, fin_mask;
    uint8_t  flags_or[2];
    double   first_ts, last_ts;
    uint64_t pkts[2], bytes[2], payload[2];

    /* TCP: uzgadnianie trójetapowe */
    double   syn_ts, synack_ts, hs_ts;
    double   rtt;                /* SYN -> końcowy ACK [s], -1 = brak       */
    uint32_t syn_retx;

    /* TCP: analiza numerów sekwencyjnych */
    uint8_t  seq_valid[2], ack_valid[2];
    uint32_t next_seq[2];        /* najwyższy oczekiwany numer sekwencyjny  */
    uint32_t last_ack[2];
    uint16_t last_win[2];
    double   gap_ts[2];
    uint32_t data_segs[2], retrans[2], ooo[2], dupack[2], zerowin[2];
    uint32_t gaps[2], keepalive[2];
    uint16_t mss[2];
    int8_t   wscale[2];
} flow_t;

typedef struct {
    flow_t **buckets;
    size_t   nbuckets;
    size_t   active;             /* liczba przepływów w tablicy mieszającej */
    flow_t **list;               /* wszystkie przepływy (kolejność utworzenia) */
    size_t   n, cap;
} flow_table_t;

void flow_table_init(flow_table_t *t);
void flow_table_free(flow_table_t *t);

/* Zwraca przepływ, do którego należy pakiet (tworzy nowy w razie potrzeby).
 * *dir otrzymuje kierunek pakietu, *created = 1 dla nowego przepływu. */
flow_t *flow_table_get(flow_table_t *t, const pkt_t *p, double idle_timeout,
                       int *dir, int *created);

unsigned flow_update(flow_t *f, const pkt_t *p, int dir);
flow_class_t flow_classify(const flow_t *f);
const char *flow_class_name(flow_class_t c);

static inline const ip_addr_t *flow_cli(const flow_t *f)
{
    return f->init == 0 ? &f->key.a : &f->key.b;
}
static inline const ip_addr_t *flow_srv(const flow_t *f)
{
    return f->init == 0 ? &f->key.b : &f->key.a;
}
static inline uint16_t flow_cport(const flow_t *f)
{
    return f->init == 0 ? f->key.pa : f->key.pb;
}
static inline uint16_t flow_sport(const flow_t *f)
{
    return f->init == 0 ? f->key.pb : f->key.pa;
}

#endif
