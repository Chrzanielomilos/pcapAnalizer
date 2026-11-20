/*
 * analyzer.h - kontekst analizy pojedynczego pliku pcap: konfiguracja
 * progów, statystyki globalne, przepływy, hosty, szeregi czasowe, DNS
 * i lista wykrytych nieprawidłowości.
 */
#ifndef PA_ANALYZER_H
#define PA_ANALYZER_H

#include "flow.h"
#include "stats.h"

/* Podział ruchu wg protokołu (statystyki globalne). */
enum { PB_TCP = 0, PB_UDP, PB_ICMP, PB_OTHERIP, PB_NONIP, PB_COUNT };

/* Niedozwolone kombinacje flag TCP. */
enum { INV_NULL = 0, INV_XMAS, INV_SYNFIN, INV_SYNRST, INV_FIN_NOACK, INV_COUNT };

typedef struct {
    int    scan_ports;           /* skan pionowy: min. liczba portów          */
    int    scan_hosts;           /* skan poziomy: min. liczba hostów          */
    double scan_fail_ratio;      /* min. udział prób bez odpowiedzi           */
    int    synflood_halfopen;    /* SYN flood: min. liczba półotwartych       */
    double synflood_ratio;       /* SYN flood: min. udział półotwartych       */
    int    udpflood_pkts;        /* UDP flood: min. liczba pakietów           */
    double udpflood_pps;         /* UDP flood: min. średnie natężenie [pkt/s] */
    double udpflood_resp_ratio;  /* UDP flood: maks. stosunek odpowiedzi      */
    double retrans_rate;         /* globalny udział retransmisji              */
    double flow_retrans_rate;    /* udział retransmisji w przepływie          */
    int    flow_min_segs;        /* min. liczba segmentów danych w przepływie */
    int    dns_suspicious;       /* min. liczba podejrzanych zapytań DNS      */
    double nxdomain_ratio;       /* udział odpowiedzi NXDOMAIN                */
    double spike_k;              /* krotność MAD dla skoków natężenia         */
    double spike_min_pps;        /* min. natężenie uznawane za skok [pkt/s]   */
    int    beacon_min_flows;     /* beaconing: min. liczba połączeń           */
    double beacon_max_cv;        /* beaconing: maks. wsp. zmienności odstępów */
    double beacon_min_interval;  /* beaconing: min. średni odstęp [s]         */
    double rst_ratio;            /* udział połączeń zerwanych RST             */
    int    unanswered_min;       /* min. liczba nieudanych prób połączeń      */
    double idle_timeout;         /* czas bezczynności kończący przepływ [s]   */
    int    top_n;                /* długość list rankingowych                 */
} config_t;

typedef struct {
    uint64_t pkts, bytes;
    uint64_t pb_pkts[PB_COUNT], pb_bytes[PB_COUNT];
    uint64_t ipv4, ipv6, vlan, frags, truncated, malformed, bad_ipcksum;
    uint64_t snap_truncated, unsupported;
    uint64_t tcp_payload, udp_payload;
    uint32_t min_len, max_len;
    double   first_ts, last_ts, prev_ts;
    int      have_ts;
    uint64_t ts_backwards;
    uint64_t size_hist[PC_COUNT][SIZE_BINS];
    uint64_t flag_bits[8];
    uint64_t syn_only, synack, pure_ack, fin_pkts, rst_pkts, psh_pkts;
    uint64_t inv[INV_COUNT];
    ip_addr_t inv_src[INV_COUNT], inv_dst[INV_COUNT];
} gstats_t;

typedef enum { SEV_INFO = 0, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_COUNT } severity_t;

typedef struct {
    severity_t sev;
    int        seq;
    char       category[64];
    char       title[200];
    char       detail[1600];
    double     t_start, t_end;   /* względem początku zapisu; < 0 = brak */
} anomaly_t;

typedef struct {
    char     path[1024];
    char     name[256];
    int      datalink;
    char     datalink_name[96];
    char     read_warning[256];
    config_t cfg;

    gstats_t     g;
    flow_table_t flows;
    host_table_t hosts;
    timeseries_t ts;
    dns_stats_t  dns;

    anomaly_t *anom;
    size_t     nanom, capanom;

    /* wyniki przetwarzania końcowego (analysis_finalize) */
    double   duration;
    uint64_t fc_count[FC_COUNT];
    uint64_t tcp_flows, udp_flows, tcp_established;
    uint64_t retrans_total, ooo_total, dupack_total, zerowin_total;
    uint64_t data_segs_total, keepalive_total, gaps_total, syn_retx_total;
    double  *rtts;
    size_t   nrtt;
    double   rtt_mean, rtt_median, rtt_p95, rtt_max;
} analysis_t;

void config_defaults(config_t *c);
int  config_set(config_t *c, const char *key_value);
void config_print(FILE *out, const config_t *c);

void analysis_init(analysis_t *a, const config_t *cfg);
int  analysis_run(analysis_t *a, const char *path, char *err, size_t errlen);
void analysis_finalize(analysis_t *a);
void analysis_free(analysis_t *a);

void analysis_add_anomaly(analysis_t *a, severity_t sev, const char *category,
                          double t_start, double t_end, const char *title,
                          const char *fmt, ...)
    __attribute__((format(printf, 7, 8)));

const char *severity_name(severity_t s);
severity_t  analysis_max_severity(const analysis_t *a);
int         analysis_count_severity(const analysis_t *a, severity_t s);

int  analysis_write_flows_csv(const analysis_t *a, const char *path);
void analysis_print_summary(const analysis_t *a, FILE *out);

#endif
