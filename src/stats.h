/*
 * stats.h - agregatory statystyk: adaptacyjne szeregi czasowe, tablica
 * hostów, histogram rozmiarów pakietów i statystyki DNS.
 */
#ifndef PA_STATS_H
#define PA_STATS_H

#include "decoder.h"

/* Klasy protokołów w szeregach czasowych i histogramach. */
enum { PC_TCP = 0, PC_UDP, PC_OTHER, PC_COUNT };

/* ---------- szeregi czasowe ---------- */

#define TS_MAX_BINS 4096

typedef struct {
    uint64_t pkts[PC_COUNT];
    uint64_t bytes[PC_COUNT];
    uint32_t syn, synack, rst, retrans, dupack, zerowin, ooo, newflows;
} ts_bin_t;

/* Szereg o stałej liczbie przedziałów: gdy czas zapisu przekracza
 * TS_MAX_BINS * width, sąsiednie przedziały są scalane, a szerokość
 * przedziału podwajana. Pamięć nie zależy od długości zapisu. */
typedef struct {
    double    t0;
    double    width;
    int       started;
    size_t    n;
    ts_bin_t *bins;
} timeseries_t;

void      ts_init(timeseries_t *ts, double initial_width);
void      ts_free(timeseries_t *ts);
ts_bin_t *ts_bin(timeseries_t *ts, double t);
void      ts_bin_add(ts_bin_t *dst, const ts_bin_t *src);
uint64_t  ts_bin_pkts(const ts_bin_t *b);
/* Agregacja do co najwyżej max_bins przedziałów o szerokości >= min_width.
 * Zwraca nowo zaalokowaną tablicę (zwolnić free()). */
ts_bin_t *ts_rebin(const timeseries_t *ts, size_t max_bins, double min_width,
                   size_t *n_out, double *w_out);

/* ---------- hosty ---------- */

typedef struct {
    ip_addr_t ip;
    uint64_t  pkts_out, pkts_in, bytes_out, bytes_in;
    uint32_t  flows_init, flows_resp;
} host_t;

typedef struct {
    host_t  *items;
    int32_t *next;
    size_t   n, cap;
    int32_t *buckets;
    size_t   nbuckets;
} host_table_t;

void    host_table_init(host_table_t *t);
void    host_table_free(host_table_t *t);
/* Uwaga: zwrócony wskaźnik traci ważność po kolejnym wywołaniu host_get(). */
host_t *host_get(host_table_t *t, const ip_addr_t *ip);

/* ---------- rozmiary pakietów ---------- */

#define SIZE_BINS 7
extern const char *const SIZE_BIN_LABELS[SIZE_BINS];
int size_bin(uint32_t len);

/* ---------- DNS ---------- */

#define DNS_NAME_LEN 256

typedef struct {
    ip_addr_t src;
    uint32_t  count;
    double    first_ts, last_ts;
    char      example[DNS_NAME_LEN];
} dns_susp_t;

typedef struct {
    uint64_t queries, responses, nxdomain, servfail, malformed;
    uint64_t qt_a, qt_aaaa, qt_txt, qt_mx, qt_any, qt_other;
    uint64_t suspicious;
    uint32_t max_qname;
    double   qname_sum;
    char     longest[DNS_NAME_LEN];
    dns_susp_t *susp;
    size_t      nsusp, capsusp;
} dns_stats_t;

void   dns_process(dns_stats_t *d, const pkt_t *p);
void   dns_free(dns_stats_t *d);
double shannon_entropy(const char *s, size_t n);

#endif
