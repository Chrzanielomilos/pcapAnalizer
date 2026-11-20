/*
 * analyzer.c - odczyt pliku pcap (libpcap), przetwarzanie strumieniowe
 * pakietów, przetwarzanie końcowe, eksport CSV i podsumowanie tekstowe.
 */
#include "analyzer.h"

#include <math.h>
#include <pcap/pcap.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* ======================= konfiguracja ======================= */

void config_defaults(config_t *c)
{
    memset(c, 0, sizeof *c);
    c->scan_ports = 50;
    c->scan_hosts = 30;
    c->scan_fail_ratio = 0.5;
    c->synflood_halfopen = 200;
    c->synflood_ratio = 0.7;
    c->udpflood_pkts = 2000;
    c->udpflood_pps = 300.0;
    c->udpflood_resp_ratio = 0.1;
    c->retrans_rate = 0.03;
    c->flow_retrans_rate = 0.05;
    c->flow_min_segs = 20;
    c->dns_suspicious = 5;
    c->nxdomain_ratio = 0.3;
    c->spike_k = 6.0;
    c->spike_min_pps = 300.0;
    c->beacon_min_flows = 6;
    c->beacon_max_cv = 0.15;
    c->beacon_min_interval = 1.0;
    c->rst_ratio = 0.3;
    c->unanswered_min = 20;
    c->idle_timeout = 300.0;
    c->top_n = 10;
}

typedef struct {
    const char *key;
    char        type;     /* 'i' = int, 'd' = double */
    size_t      off;
    const char *desc;
} cfgkey_t;

#define CK(k, t, f, d) { k, t, offsetof(config_t, f), d }
static const cfgkey_t CFG_KEYS[] = {
    CK("scan_ports",          'i', scan_ports,          "skan pionowy: min. liczba różnych portów jednego hosta"),
    CK("scan_hosts",          'i', scan_hosts,          "skan poziomy: min. liczba różnych hostów na tym samym porcie"),
    CK("scan_fail_ratio",     'd', scan_fail_ratio,     "skan: min. udział prób bez odpowiedzi/odrzuconych"),
    CK("synflood_halfopen",   'i', synflood_halfopen,   "SYN flood: min. liczba połączeń półotwartych do usługi"),
    CK("synflood_ratio",      'd', synflood_ratio,      "SYN flood: min. udział połączeń półotwartych"),
    CK("udpflood_pkts",       'i', udpflood_pkts,       "UDP flood: min. liczba pakietów do usługi"),
    CK("udpflood_pps",        'd', udpflood_pps,        "UDP flood: min. średnie natężenie [pakiety/s]"),
    CK("udpflood_resp_ratio", 'd', udpflood_resp_ratio, "UDP flood: maks. stosunek pakietów odpowiedzi do żądań"),
    CK("retrans_rate",        'd', retrans_rate,        "TCP: globalny próg udziału retransmisji"),
    CK("flow_retrans_rate",   'd', flow_retrans_rate,   "TCP: próg udziału retransmisji w przepływie"),
    CK("flow_min_segs",       'i', flow_min_segs,       "TCP: min. liczba segmentów danych przepływu do oceny"),
    CK("dns_suspicious",      'i', dns_suspicious,      "DNS: min. liczba podejrzanych zapytań z hosta"),
    CK("nxdomain_ratio",      'd', nxdomain_ratio,      "DNS: próg udziału odpowiedzi NXDOMAIN"),
    CK("spike_k",             'd', spike_k,             "skoki natężenia: krotność odchylenia MAD"),
    CK("spike_min_pps",       'd', spike_min_pps,       "skoki natężenia: min. natężenie [pakiety/s]"),
    CK("beacon_min_flows",    'i', beacon_min_flows,    "beaconing: min. liczba powtórzonych połączeń"),
    CK("beacon_max_cv",       'd', beacon_max_cv,       "beaconing: maks. współczynnik zmienności odstępów"),
    CK("beacon_min_interval", 'd', beacon_min_interval, "beaconing: min. średni odstęp między połączeniami [s]"),
    CK("rst_ratio",           'd', rst_ratio,           "TCP: próg udziału połączeń zerwanych przez RST"),
    CK("unanswered_min",      'i', unanswered_min,      "TCP: min. liczba nieudanych prób połączeń"),
    CK("idle_timeout",        'd', idle_timeout,        "przepływ: czas bezczynności rozpoczynający nowy przepływ [s]"),
    CK("top_n",               'i', top_n,               "długość list rankingowych w raporcie"),
};

int config_set(config_t *c, const char *kv)
{
    const char *eq = strchr(kv, '=');
    if (!eq || eq == kv || eq[1] == '\0')
        return -1;
    size_t kl = (size_t)(eq - kv);
    for (size_t i = 0; i < ARRAY_LEN(CFG_KEYS); i++) {
        const cfgkey_t *k = &CFG_KEYS[i];
        if (strlen(k->key) != kl || strncmp(k->key, kv, kl) != 0)
            continue;
        char *end = NULL;
        if (k->type == 'i') {
            long v = strtol(eq + 1, &end, 10);
            if (*end != '\0' || v < 0 || v > 100000000L)
                return -1;
            *(int *)((char *)c + k->off) = (int)v;
        } else {
            double v = strtod(eq + 1, &end);
            if (*end != '\0' || v < 0)
                return -1;
            *(double *)((char *)c + k->off) = v;
        }
        if (c->top_n < 1)
            c->top_n = 1;
        if (c->top_n > 50)
            c->top_n = 50;
        return 0;
    }
    return -1;
}

void config_print(FILE *out, const config_t *c)
{
    for (size_t i = 0; i < ARRAY_LEN(CFG_KEYS); i++) {
        const cfgkey_t *k = &CFG_KEYS[i];
        if (k->type == 'i')
            fprintf(out, "  %-20s = %-8d %s\n", k->key,
                    *(const int *)((const char *)c + k->off), k->desc);
        else
            fprintf(out, "  %-20s = %-8g %s\n", k->key,
                    *(const double *)((const char *)c + k->off), k->desc);
    }
}

/* ======================= cykl życia ======================= */

void analysis_init(analysis_t *a, const config_t *cfg)
{
    memset(a, 0, sizeof *a);
    a->cfg = *cfg;
    flow_table_init(&a->flows);
    host_table_init(&a->hosts);
    ts_init(&a->ts, 0.001);
}

void analysis_free(analysis_t *a)
{
    flow_table_free(&a->flows);
    host_table_free(&a->hosts);
    ts_free(&a->ts);
    dns_free(&a->dns);
    free(a->anom);
    free(a->rtts);
    memset(a, 0, sizeof *a);
}

/* ======================= przetwarzanie pakietów ======================= */

static void tcp_flag_stats(analysis_t *a, const pkt_t *p, ts_bin_t *bin)
{
    gstats_t *g = &a->g;
    uint8_t f = p->tcp_flags;

    for (int b = 0; b < 8; b++)
        if (f & (1u << b))
            g->flag_bits[b]++;
    if ((f & (TCP_SYN | TCP_ACK)) == TCP_SYN) {
        g->syn_only++;
        bin->syn++;
    }
    if ((f & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
        g->synack++;
        bin->synack++;
    }
    if (f & TCP_RST) {
        g->rst_pkts++;
        bin->rst++;
    }
    if (f & TCP_FIN)
        g->fin_pkts++;
    if (f & TCP_PSH)
        g->psh_pkts++;
    if (f == TCP_ACK && p->l4_payload_len == 0)
        g->pure_ack++;

    int inv = -1;
    if ((f & 0x3F) == 0)
        inv = INV_NULL;
    else if ((f & (TCP_FIN | TCP_PSH | TCP_URG)) == (TCP_FIN | TCP_PSH | TCP_URG) &&
             !(f & (TCP_SYN | TCP_RST | TCP_ACK)))
        inv = INV_XMAS;
    else if ((f & (TCP_SYN | TCP_FIN)) == (TCP_SYN | TCP_FIN))
        inv = INV_SYNFIN;
    else if ((f & (TCP_SYN | TCP_RST)) == (TCP_SYN | TCP_RST))
        inv = INV_SYNRST;
    else if ((f & TCP_FIN) && !(f & TCP_ACK))
        inv = INV_FIN_NOACK;
    if (inv >= 0) {
        if (g->inv[inv] == 0) {
            g->inv_src[inv] = p->src;
            g->inv_dst[inv] = p->dst;
        }
        g->inv[inv]++;
    }
}

static void count_other(analysis_t *a, ts_bin_t *bin, int pb, uint32_t len)
{
    a->g.pb_pkts[pb]++;
    a->g.pb_bytes[pb] += len;
    a->g.size_hist[PC_OTHER][size_bin(len)]++;
    bin->pkts[PC_OTHER]++;
    bin->bytes[PC_OTHER] += len;
}

static void process_packet(analysis_t *a, const struct pcap_pkthdr *h,
                           const uint8_t *data)
{
    gstats_t *g = &a->g;
    double ts = (double)h->ts.tv_sec + (double)h->ts.tv_usec / 1e6;
    uint32_t len = h->len;
    pkt_t p;
    int st = decode_packet(a->datalink, ts, h->caplen, h->len, data, &p);

    g->pkts++;
    g->bytes += len;
    if (!g->have_ts) {
        g->have_ts = 1;
        g->first_ts = g->last_ts = g->prev_ts = ts;
        g->min_len = g->max_len = len;
    } else {
        if (ts < g->prev_ts)
            g->ts_backwards++;
        if (ts > g->last_ts)
            g->last_ts = ts;
        g->prev_ts = ts;
        if (len < g->min_len)
            g->min_len = len;
        if (len > g->max_len)
            g->max_len = len;
    }

    ts_bin_t *bin = ts_bin(&a->ts, ts);

    if (st == DEC_UNSUPPORTED_LINK) {
        g->unsupported++;
        count_other(a, bin, PB_NONIP, len);
        return;
    }
    if (st == DEC_NOT_IP) {
        count_other(a, bin, PB_NONIP, len);
        return;
    }
    if (p.ipver == 0) {      /* uszkodzony lub obcięty nagłówek L2/IP */
        if (st == DEC_TRUNCATED)
            g->truncated++;
        else
            g->malformed++;
        count_other(a, bin, PB_OTHERIP, len);
        return;
    }

    if (p.ipver == 4)
        g->ipv4++;
    else
        g->ipv6++;
    if (p.vlan_tags)
        g->vlan++;
    if (p.frag)
        g->frags++;
    if (p.ip_cksum_bad)
        g->bad_ipcksum++;
    if (p.snap_truncated)
        g->snap_truncated++;
    if (st == DEC_TRUNCATED)
        g->truncated++;
    else if (st == DEC_MALFORMED)
        g->malformed++;

    int pb, pc;
    switch (p.proto) {
    case IPP_TCP:   pb = PB_TCP;     pc = PC_TCP;   break;
    case IPP_UDP:   pb = PB_UDP;     pc = PC_UDP;   break;
    case IPP_ICMP:
    case IPP_ICMP6: pb = PB_ICMP;    pc = PC_OTHER; break;
    default:        pb = PB_OTHERIP; pc = PC_OTHER; break;
    }
    g->pb_pkts[pb]++;
    g->pb_bytes[pb] += len;
    g->size_hist[pc][size_bin(len)]++;
    bin->pkts[pc]++;
    bin->bytes[pc] += len;

    {
        host_t *hs = host_get(&a->hosts, &p.src);
        hs->pkts_out++;
        hs->bytes_out += len;
    }
    {
        host_t *hd = host_get(&a->hosts, &p.dst);
        hd->pkts_in++;
        hd->bytes_in += len;
    }

    if (!p.l4_valid || (pc != PC_TCP && pc != PC_UDP))
        return;

    if (pc == PC_TCP) {
        g->tcp_payload += p.l4_payload_len;
        tcp_flag_stats(a, &p, bin);
    } else {
        g->udp_payload += p.l4_payload_len;
    }

    int dir, created;
    flow_t *f = flow_table_get(&a->flows, &p, a->cfg.idle_timeout, &dir, &created);
    if (created)
        bin->newflows++;
    unsigned ev = flow_update(f, &p, dir);
    if (ev & EV_RETRANS)
        bin->retrans++;
    if (ev & EV_OOO)
        bin->ooo++;
    if (ev & EV_DUPACK)
        bin->dupack++;
    if (ev & EV_ZEROWIN)
        bin->zerowin++;

    if (pc == PC_UDP && (p.sport == 53 || p.dport == 53))
        dns_process(&a->dns, &p);
}

int analysis_run(analysis_t *a, const char *path, char *err, size_t errlen)
{
    char ebuf[PCAP_ERRBUF_SIZE] = "";
    pcap_t *pc = pcap_open_offline(path, ebuf);
    if (!pc) {
        snprintf(err, errlen, "%s", ebuf);
        return -1;
    }

    snprintf(a->path, sizeof a->path, "%s", path);
    const char *base = strrchr(path, '/');
    snprintf(a->name, sizeof a->name, "%s", base ? base + 1 : path);
    a->datalink = pcap_datalink(pc);
    const char *dn = pcap_datalink_val_to_name(a->datalink);
    const char *dd = pcap_datalink_val_to_description(a->datalink);
    snprintf(a->datalink_name, sizeof a->datalink_name, "%s (%s)",
             dn ? dn : "?", dd ? dd : "nieznany");

    struct pcap_pkthdr *h;
    const u_char *data;
    int rc;
    while ((rc = pcap_next_ex(pc, &h, &data)) == 1)
        process_packet(a, h, data);
    if (rc == -1)   /* np. obcięty plik - wyniki częściowe są zachowane */
        snprintf(a->read_warning, sizeof a->read_warning,
                 "przerwano odczyt: %s", pcap_geterr(pc));
    pcap_close(pc);
    return 0;
}

/* ======================= przetwarzanie końcowe ======================= */

static int cmp_double(const void *x, const void *y)
{
    double a = *(const double *)x, b = *(const double *)y;
    return (a > b) - (a < b);
}

void analysis_finalize(analysis_t *a)
{
    a->duration = a->g.have_ts ? a->g.last_ts - a->g.first_ts : 0.0;

    size_t cap = 0;
    for (size_t i = 0; i < a->flows.n; i++) {
        const flow_t *f = a->flows.list[i];
        a->fc_count[flow_classify(f)]++;
        if (f->key.proto == IPP_TCP) {
            a->tcp_flows++;
            for (int d = 0; d < 2; d++) {
                a->retrans_total += f->retrans[d];
                a->ooo_total += f->ooo[d];
                a->dupack_total += f->dupack[d];
                a->zerowin_total += f->zerowin[d];
                a->data_segs_total += f->data_segs[d];
                a->keepalive_total += f->keepalive[d];
                a->gaps_total += f->gaps[d];
            }
            a->syn_retx_total += f->syn_retx;
            if (f->saw_hs_ack)
                a->tcp_established++;
            if (f->rtt >= 0) {
                if (a->nrtt == cap) {
                    cap = cap ? cap * 2 : 256;
                    a->rtts = xrealloc(a->rtts, cap * sizeof *a->rtts);
                }
                a->rtts[a->nrtt++] = f->rtt;
            }
        } else {
            a->udp_flows++;
        }
        {
            host_t *hc = host_get(&a->hosts, flow_cli(f));
            hc->flows_init++;
        }
        {
            host_t *hs = host_get(&a->hosts, flow_srv(f));
            hs->flows_resp++;
        }
    }

    if (a->nrtt) {
        qsort(a->rtts, a->nrtt, sizeof *a->rtts, cmp_double);
        double sum = 0;
        for (size_t i = 0; i < a->nrtt; i++)
            sum += a->rtts[i];
        a->rtt_mean = sum / (double)a->nrtt;
        a->rtt_median = a->rtts[a->nrtt / 2];
        a->rtt_p95 = a->rtts[(size_t)(0.95 * (double)(a->nrtt - 1))];
        a->rtt_max = a->rtts[a->nrtt - 1];
    }
}

/* ======================= nieprawidłowości ======================= */

void analysis_add_anomaly(analysis_t *a, severity_t sev, const char *category,
                          double t_start, double t_end, const char *title,
                          const char *fmt, ...)
{
    if (a->nanom == a->capanom) {
        a->capanom = a->capanom ? a->capanom * 2 : 16;
        a->anom = xrealloc(a->anom, a->capanom * sizeof *a->anom);
    }
    anomaly_t *x = &a->anom[a->nanom];
    memset(x, 0, sizeof *x);
    x->sev = sev;
    x->seq = (int)a->nanom;
    x->t_start = t_start;
    x->t_end = t_end;
    snprintf(x->category, sizeof x->category, "%s", category);
    snprintf(x->title, sizeof x->title, "%s", title);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(x->detail, sizeof x->detail, fmt, ap);
    va_end(ap);
    a->nanom++;
}

const char *severity_name(severity_t s)
{
    switch (s) {
    case SEV_HIGH:   return "WYSOKI";
    case SEV_MEDIUM: return "ŚREDNI";
    case SEV_LOW:    return "NISKI";
    default:         return "INFO";
    }
}

severity_t analysis_max_severity(const analysis_t *a)
{
    severity_t m = SEV_INFO;
    for (size_t i = 0; i < a->nanom; i++)
        if (a->anom[i].sev > m)
            m = a->anom[i].sev;
    return m;
}

int analysis_count_severity(const analysis_t *a, severity_t s)
{
    int n = 0;
    for (size_t i = 0; i < a->nanom; i++)
        if (a->anom[i].sev == s)
            n++;
    return n;
}

/* ======================= eksport ======================= */

int analysis_write_flows_csv(const analysis_t *a, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    fprintf(f, "id,proto,client,client_port,server,server_port,start_rel_s,"
               "duration_s,pkts_c2s,pkts_s2c,bytes_c2s,bytes_s2c,"
               "payload_c2s,payload_s2c,state,handshake_rtt_ms,retrans,"
               "out_of_order,dup_ack,zero_window\n");
    for (size_t i = 0; i < a->flows.n; i++) {
        const flow_t *fl = a->flows.list[i];
        char c[IPSTR_LEN], s[IPSTR_LEN];
        ip_str(flow_cli(fl), c, sizeof c);
        ip_str(flow_srv(fl), s, sizeof s);
        fprintf(f, "%u,%s,%s,%u,%s,%u,%.6f,%.6f,%llu,%llu,%llu,%llu,%llu,%llu,"
                   "\"%s\",%.3f,%u,%u,%u,%u\n",
                fl->id, proto_name(fl->key.proto), c, (unsigned)flow_cport(fl),
                s, (unsigned)flow_sport(fl), fl->first_ts - a->g.first_ts,
                fl->last_ts - fl->first_ts,
                (unsigned long long)fl->pkts[0], (unsigned long long)fl->pkts[1],
                (unsigned long long)fl->bytes[0], (unsigned long long)fl->bytes[1],
                (unsigned long long)fl->payload[0], (unsigned long long)fl->payload[1],
                flow_class_name(flow_classify(fl)),
                fl->rtt >= 0 ? fl->rtt * 1000.0 : -1.0,
                fl->retrans[0] + fl->retrans[1], fl->ooo[0] + fl->ooo[1],
                fl->dupack[0] + fl->dupack[1], fl->zerowin[0] + fl->zerowin[1]);
    }
    int rc = ferror(f) ? -1 : 0;
    if (fclose(f) != 0)
        rc = -1;
    return rc;
}

void analysis_print_summary(const analysis_t *a, FILE *out)
{
    char b1[64], b2[64], b3[64];
    fmt_count(a->g.pkts, b1, sizeof b1);
    fmt_bytes((double)a->g.bytes, b2, sizeof b2);
    fmt_duration(a->duration, b3, sizeof b3);
    fprintf(out, "Plik: %s\n", a->path);
    fprintf(out, "  Typ łącza: %s\n", a->datalink_name);
    fprintf(out, "  Pakiety: %s, wolumen: %s, czas trwania: %s\n", b1, b2, b3);
    fmt_count(a->g.pb_pkts[PB_TCP], b1, sizeof b1);
    fmt_count(a->g.pb_pkts[PB_UDP], b2, sizeof b2);
    fprintf(out, "  Pakiety TCP: %s, UDP: %s, IPv4: %llu, IPv6: %llu\n", b1, b2,
            (unsigned long long)a->g.ipv4, (unsigned long long)a->g.ipv6);
    fprintf(out, "  Przepływy TCP: %llu, UDP: %llu, hosty: %zu\n",
            (unsigned long long)a->tcp_flows, (unsigned long long)a->udp_flows,
            a->hosts.n);
    if (a->read_warning[0])
        fprintf(out, "  Ostrzeżenie: %s\n", a->read_warning);
    fprintf(out, "  Nieprawidłowości: %zu (wysokie: %d, średnie: %d, niskie: %d, info: %d)\n",
            a->nanom, analysis_count_severity(a, SEV_HIGH),
            analysis_count_severity(a, SEV_MEDIUM),
            analysis_count_severity(a, SEV_LOW),
            analysis_count_severity(a, SEV_INFO));
    for (size_t i = 0; i < a->nanom; i++)
        fprintf(out, "    [%s] %s\n", severity_name(a->anom[i].sev), a->anom[i].title);
}
