/*
 * anomaly.c - detektory nieprawidłowości.
 *
 * Detektory działają na zbiorze rekordów przepływów (frec_t) sortowanym
 * według różnych kluczy, co pozwala policzyć liczności (np. liczbę
 * różnych portów jednego hosta) w czasie O(n log n) bez dodatkowych
 * tablic mieszających.
 */
#include "anomaly.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#define CAT_RECON   "Rekonesans"
#define CAT_DOS     "Odmowa usługi (DoS)"
#define CAT_TCP     "Jakość połączeń TCP"
#define CAT_PROTO   "Naruszenie protokołu"
#define CAT_DNS     "DNS"
#define CAT_VOLUME  "Natężenie ruchu"
#define CAT_PATTERN "Wzorzec komunikacji"
#define CAT_QUALITY "Jakość danych"

typedef struct {
    const flow_t    *f;
    const ip_addr_t *cli, *srv;
    uint16_t         port;     /* port usługi (strony odpowiadającej) */
    uint8_t          proto;
    uint8_t          ok;       /* strona odpowiadająca odpowiedziała   */
    uint8_t          cls;
    double           start;
} frec_t;

static double rel(const analysis_t *a, double ts)
{
    return ts - a->g.first_ts;
}

static int flow_answered(const flow_t *f)
{
    if (f->key.proto == IPP_TCP) {
        if (f->saw_synack)
            return 1;
        return f->midstream && f->pkts[1] > 0 && !(f->flags_or[1] & TCP_RST);
    }
    return f->pkts[1] > 0;
}

static frec_t *build_recs(const analysis_t *a, size_t *n)
{
    frec_t *r = xmalloc(a->flows.n * sizeof *r);
    for (size_t i = 0; i < a->flows.n; i++) {
        const flow_t *f = a->flows.list[i];
        r[i].f = f;
        r[i].cli = flow_cli(f);
        r[i].srv = flow_srv(f);
        r[i].port = flow_sport(f);
        r[i].proto = f->key.proto;
        r[i].ok = (uint8_t)flow_answered(f);
        r[i].cls = (uint8_t)flow_classify(f);
        r[i].start = f->first_ts;
    }
    *n = a->flows.n;
    return r;
}

static int cmp_num(double x, double y)
{
    return (x > y) - (x < y);
}

static int cmp_double_asc(const void *pa, const void *pb)
{
    return cmp_num(*(const double *)pa, *(const double *)pb);
}

/* klucz: klient, serwer, protokół, port, czas */
static int cmp_cli_srv_port(const void *pa, const void *pb)
{
    const frec_t *x = pa, *y = pb;
    int c;
    if ((c = ip_cmp(x->cli, y->cli)) != 0) return c;
    if ((c = ip_cmp(x->srv, y->srv)) != 0) return c;
    if ((c = cmp_num(x->proto, y->proto)) != 0) return c;
    if ((c = cmp_num(x->port, y->port)) != 0) return c;
    return cmp_num(x->start, y->start);
}

/* klucz: klient, protokół, port, serwer */
static int cmp_cli_port_srv(const void *pa, const void *pb)
{
    const frec_t *x = pa, *y = pb;
    int c;
    if ((c = ip_cmp(x->cli, y->cli)) != 0) return c;
    if ((c = cmp_num(x->proto, y->proto)) != 0) return c;
    if ((c = cmp_num(x->port, y->port)) != 0) return c;
    if ((c = ip_cmp(x->srv, y->srv)) != 0) return c;
    return cmp_num(x->start, y->start);
}

/* klucz: serwer, protokół, port, klient */
static int cmp_srv_port_cli(const void *pa, const void *pb)
{
    const frec_t *x = pa, *y = pb;
    int c;
    if ((c = ip_cmp(x->srv, y->srv)) != 0) return c;
    if ((c = cmp_num(x->proto, y->proto)) != 0) return c;
    if ((c = cmp_num(x->port, y->port)) != 0) return c;
    if ((c = ip_cmp(x->cli, y->cli)) != 0) return c;
    return cmp_num(x->start, y->start);
}

static int has_category(const analysis_t *a, const char *cat)
{
    for (size_t i = 0; i < a->nanom; i++)
        if (strcmp(a->anom[i].category, cat) == 0)
            return 1;
    return 0;
}

/* ---------------- skanowanie pionowe (wiele portów jednego hosta) ---------------- */

static void detect_vertical_scan(analysis_t *a, frec_t *r, size_t n)
{
    qsort(r, n, sizeof *r, cmp_cli_srv_port);
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && ip_cmp(r[j].cli, r[i].cli) == 0 &&
               ip_cmp(r[j].srv, r[i].srv) == 0 && r[j].proto == r[i].proto)
            j++;

        size_t ports = 0, ports_ok = 0;
        double t0 = r[i].start, t1 = r[i].start;
        char open[400] = "";
        for (size_t k = i; k < j;) {
            size_t m = k;
            int ok = 0;
            while (m < j && r[m].port == r[k].port) {
                ok |= r[m].ok;
                if (r[m].start < t0) t0 = r[m].start;
                if (r[m].start > t1) t1 = r[m].start;
                m++;
            }
            ports++;
            if (ok) {
                ports_ok++;
                if (ports_ok <= 12) {
                    const char *svc = service_name(r[k].proto, r[k].port);
                    if (svc)
                        sappend(open, sizeof open, "%s%u (%s)", ports_ok > 1 ? ", " : "",
                                (unsigned)r[k].port, svc);
                    else
                        sappend(open, sizeof open, "%s%u", ports_ok > 1 ? ", " : "",
                                (unsigned)r[k].port);
                } else if (ports_ok == 13) {
                    sappend(open, sizeof open, ", …");
                }
            }
            k = m;
        }

        if ((int)ports >= a->cfg.scan_ports) {
            double fail = 1.0 - (double)ports_ok / (double)ports;
            if (fail >= a->cfg.scan_fail_ratio || ports >= (size_t)a->cfg.scan_ports * 4) {
                char cs[IPSTR_LEN], ss[IPSTR_LEN], dur[32], rate[32], pf[16], title[200];
                ip_str(r[i].cli, cs, sizeof cs);
                ip_str(r[i].srv, ss, sizeof ss);
                fmt_duration(t1 - t0, dur, sizeof dur);
                fmt_compact((double)ports / PA_MAX(t1 - t0, 0.001), rate, sizeof rate);
                fmt_percent(fail, pf, sizeof pf);
                snprintf(title, sizeof title, "Skanowanie portów %s: %s → %s",
                         proto_name(r[i].proto), cs, ss);
                analysis_add_anomaly(a, fail >= a->cfg.scan_fail_ratio ? SEV_HIGH : SEV_MEDIUM,
                    CAT_RECON, rel(a, t0), rel(a, t1), title,
                    "Host %s zainicjował połączenia %s do %zu różnych portów hosta %s "
                    "w ciągu %s (ok. %s portów/s). %s prób pozostało bez odpowiedzi "
                    "lub zostało odrzuconych. %s%s%s Wzorzec odpowiada skanowaniu "
                    "pionowemu (np. nmap -sS/-sU), czyli rozpoznaniu usług dostępnych "
                    "na hoście docelowym.",
                    cs, proto_name(r[i].proto), ports, ss, dur, rate, pf,
                    ports_ok ? "Porty, które odpowiedziały (prawdopodobnie otwarte): " :
                               "Żaden z portów nie odpowiedział.",
                    open, ports_ok ? "." : "");
            }
        }
        i = j;
    }
}

/* ---------------- skanowanie poziome (jeden port, wiele hostów) ---------------- */

static void detect_horizontal_scan(analysis_t *a, frec_t *r, size_t n)
{
    qsort(r, n, sizeof *r, cmp_cli_port_srv);
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && ip_cmp(r[j].cli, r[i].cli) == 0 &&
               r[j].proto == r[i].proto && r[j].port == r[i].port)
            j++;

        size_t hosts = 0, hosts_ok = 0;
        double t0 = r[i].start, t1 = r[i].start;
        char examples[300] = "";
        for (size_t k = i; k < j;) {
            size_t m = k;
            int ok = 0;
            while (m < j && ip_cmp(r[m].srv, r[k].srv) == 0) {
                ok |= r[m].ok;
                if (r[m].start < t0) t0 = r[m].start;
                if (r[m].start > t1) t1 = r[m].start;
                m++;
            }
            hosts++;
            if (ok)
                hosts_ok++;
            if (hosts <= 5) {
                char hs[IPSTR_LEN];
                sappend(examples, sizeof examples, "%s%s", hosts > 1 ? ", " : "",
                        ip_str(r[k].srv, hs, sizeof hs));
            }
            k = m;
        }

        double fail = hosts ? 1.0 - (double)hosts_ok / (double)hosts : 0.0;
        if ((int)hosts >= a->cfg.scan_hosts && fail >= a->cfg.scan_fail_ratio) {
            char cs[IPSTR_LEN], svc[64], dur[32], pf[16], title[200];
            ip_str(r[i].cli, cs, sizeof cs);
            fmt_service(r[i].proto, r[i].port, svc, sizeof svc);
            fmt_duration(t1 - t0, dur, sizeof dur);
            fmt_percent(fail, pf, sizeof pf);
            snprintf(title, sizeof title, "Skanowanie poziome %s: %s → %zu hostów",
                     svc, cs, hosts);
            analysis_add_anomaly(a, fail >= 0.8 ? SEV_HIGH : SEV_MEDIUM, CAT_RECON,
                rel(a, t0), rel(a, t1), title,
                "Host %s próbował połączyć się z usługą %s na %zu różnych hostach "
                "(m.in. %s%s) w ciągu %s. Odpowiedziało %zu hostów, a %s prób pozostało "
                "bez odpowiedzi lub zostało odrzuconych. Wzorzec odpowiada przeszukiwaniu "
                "sieci w poszukiwaniu hostów z daną usługą (rekonesans, propagacja "
                "złośliwego oprogramowania).",
                cs, svc, hosts, examples, hosts > 5 ? ", …" : "", dur, hosts_ok, pf);
        }
        i = j;
    }
}

/* ---------------- SYN flood i UDP flood ---------------- */

static void detect_floods(analysis_t *a, frec_t *r, size_t n)
{
    const config_t *c = &a->cfg;
    qsort(r, n, sizeof *r, cmp_srv_port_cli);
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && ip_cmp(r[j].srv, r[i].srv) == 0 &&
               r[j].proto == r[i].proto && r[j].port == r[i].port)
            j++;

        size_t total = j - i, half = 0, synack_only = 0, clients = 0;
        uint64_t fwd = 0, rev = 0, fwd_bytes = 0;
        double t0 = 1e300, t1 = -1e300, h0 = 1e300, h1 = -1e300;
        const ip_addr_t *prev = NULL;
        for (size_t k = i; k < j; k++) {
            const flow_t *f = r[k].f;
            if (!prev || ip_cmp(prev, r[k].cli) != 0) {
                clients++;
                prev = r[k].cli;
            }
            fwd += f->pkts[0];
            rev += f->pkts[1];
            fwd_bytes += f->bytes[0];
            if (f->first_ts < t0) t0 = f->first_ts;
            if (f->last_ts > t1) t1 = f->last_ts;
            if (r[k].cls == FC_UNANSWERED || r[k].cls == FC_HALF_OPEN) {
                half++;
                if (r[k].cls == FC_HALF_OPEN)
                    synack_only++;
                if (r[k].start < h0) h0 = r[k].start;
                if (r[k].start > h1) h1 = r[k].start;
            }
        }

        char ss[IPSTR_LEN], svc[64], title[200];
        ip_str(r[i].srv, ss, sizeof ss);
        fmt_service(r[i].proto, r[i].port, svc, sizeof svc);

        if (r[i].proto == IPP_TCP && (int)half >= c->synflood_halfopen &&
            (double)half / (double)total >= c->synflood_ratio) {
            char pf[16], rate[32], dur[32];
            fmt_percent((double)half / (double)total, pf, sizeof pf);
            fmt_compact((double)half / PA_MAX(h1 - h0, 0.001), rate, sizeof rate);
            fmt_duration(h1 - h0, dur, sizeof dur);
            snprintf(title, sizeof title, "SYN flood na %s (%s)", ss, svc);
            analysis_add_anomaly(a, SEV_HIGH, CAT_DOS, rel(a, h0), rel(a, h1), title,
                "Do usługi %s na hoście %s skierowano %zu prób połączeń, z czego %zu (%s) "
                "nie zakończyło uzgadniania trójetapowego; w %zu przypadkach serwer "
                "odpowiedział SYN-ACK, lecz klient nie potwierdził połączenia. Żądania "
                "pochodziły z %zu różnych adresów źródłowych%s. Średnie natężenie: %s SYN/s "
                "w okresie %s. Atak wyczerpuje kolejkę połączeń półotwartych serwera; "
                "zalecane środki zaradcze to SYN cookies, ograniczanie natężenia "
                "i filtrowanie u dostawcy.",
                svc, ss, total, half, pf, synack_only, clients,
                clients * 2 > half ? " – duża liczba unikalnych źródeł wskazuje na "
                                     "fałszowanie adresów (IP spoofing)" : "",
                rate, dur);
        }

        if (r[i].proto == IPP_UDP) {
            double dur = PA_MAX(t1 - t0, 1.0);
            double pps = (double)fwd / dur;
            if ((int64_t)fwd >= c->udpflood_pkts && pps >= c->udpflood_pps &&
                (double)rev <= (double)fwd * c->udpflood_resp_ratio) {
                char cnt[32], vol[32], rate[32], br[32], ds[32];
                fmt_count(fwd, cnt, sizeof cnt);
                fmt_bytes((double)fwd_bytes, vol, sizeof vol);
                fmt_compact(pps, rate, sizeof rate);
                fmt_bitrate((double)fwd_bytes * 8.0 / dur, br, sizeof br);
                fmt_duration(t1 - t0, ds, sizeof ds);
                snprintf(title, sizeof title, "UDP flood na %s (%s)", ss, svc);
                analysis_add_anomaly(a, SEV_HIGH, CAT_DOS, rel(a, t0), rel(a, t1), title,
                    "Host %s otrzymał %s datagramów UDP (%s) na port %u od %zu nadawców "
                    "w ciągu %s, średnio %s pakietów/s (%s), przy %llu pakietach "
                    "odpowiedzi. Duże, jednokierunkowe natężenie ruchu UDP do jednej usługi "
                    "jest charakterystyczne dla wolumetrycznego ataku odmowy usługi.",
                    ss, cnt, vol, (unsigned)r[i].port, clients, ds, rate, br,
                    (unsigned long long)rev);
            }
        }
        i = j;
    }
}

/* ---------------- okresowa komunikacja (beaconing) ---------------- */

static int infra_port(uint16_t port)
{
    static const uint16_t p[] = {53, 67, 68, 123, 137, 138, 1900, 5353};
    for (size_t i = 0; i < ARRAY_LEN(p); i++)
        if (p[i] == port)
            return 1;
    return 0;
}

static void detect_beacons(analysis_t *a, frec_t *r, size_t n)
{
    const config_t *c = &a->cfg;
    int reported = 0;
    qsort(r, n, sizeof *r, cmp_cli_srv_port);
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && ip_cmp(r[j].cli, r[i].cli) == 0 &&
               ip_cmp(r[j].srv, r[i].srv) == 0 && r[j].proto == r[i].proto &&
               r[j].port == r[i].port)
            j++;
        size_t cnt = j - i;
        if ((int)cnt >= c->beacon_min_flows && cnt >= 3) {
            double mean = (r[j - 1].start - r[i].start) / (double)(cnt - 1);
            if (mean >= c->beacon_min_interval) {
                double ss = 0;
                for (size_t k = i + 1; k < j; k++) {
                    double d = r[k].start - r[k - 1].start - mean;
                    ss += d * d;
                }
                double cv = sqrt(ss / (double)(cnt - 1)) / mean;
                if (cv <= c->beacon_max_cv && reported < 10) {
                    char cs[IPSTR_LEN], sv[IPSTR_LEN], svc[64], ms[32], cvs[16], title[200];
                    ip_str(r[i].cli, cs, sizeof cs);
                    ip_str(r[i].srv, sv, sizeof sv);
                    fmt_service(r[i].proto, r[i].port, svc, sizeof svc);
                    fmt_duration(mean, ms, sizeof ms);
                    fmt_fixed(cv, 3, cvs, sizeof cvs);
                    snprintf(title, sizeof title, "Okresowa komunikacja %s → %s (%s)",
                             cs, sv, svc);
                    int infra = infra_port(r[i].port);
                    analysis_add_anomaly(a, infra ? SEV_INFO : SEV_MEDIUM, CAT_PATTERN,
                        rel(a, r[i].start), rel(a, r[j - 1].start), title,
                        "Host %s nawiązał %zu połączeń z %s (%s) w regularnych odstępach "
                        "średnio co %s (współczynnik zmienności odstępów %s). %s",
                        cs, cnt, sv, svc, ms, cvs,
                        infra ? "Usługa należy do infrastruktury sieciowej (np. synchronizacja "
                                "czasu, DNS), więc regularność jest najpewniej zachowaniem "
                                "prawidłowym."
                              : "Tak regularna, zautomatyzowana komunikacja może być sygnałem "
                                "nawoływania serwera C2 przez złośliwe oprogramowanie "
                                "(beaconing); może też wynikać z prawidłowego działania "
                                "agentów monitoringu lub aktualizacji – wymaga weryfikacji.");
                    reported++;
                }
            }
        }
        i = j;
    }
}

/* ---------------- jakość połączeń TCP ---------------- */

typedef struct {
    const flow_t *f;
    double        rate;
    uint32_t      retr, segs;
} retr_t;

static int cmp_retr(const void *pa, const void *pb)
{
    const retr_t *x = pa, *y = pb;
    return cmp_num(y->rate, x->rate);
}

static void flow_label(const flow_t *f, char *buf, size_t n)
{
    char c[IPSTR_LEN], s[IPSTR_LEN];
    ip_str(flow_cli(f), c, sizeof c);
    ip_str(flow_srv(f), s, sizeof s);
    snprintf(buf, n, "%s:%u ↔ %s:%u", c, (unsigned)flow_cport(f), s,
             (unsigned)flow_sport(f));
}

static void detect_tcp_quality(analysis_t *a)
{
    const config_t *c = &a->cfg;

    /* globalny poziom retransmisji */
    if (a->data_segs_total >= 100) {
        double rate = (double)a->retrans_total / (double)a->data_segs_total;
        if (rate >= c->retrans_rate) {
            char pf[16], title[200];
            fmt_percent(rate, pf, sizeof pf);
            snprintf(title, sizeof title, "Podwyższony poziom retransmisji TCP (%s)", pf);
            analysis_add_anomaly(a, SEV_MEDIUM, CAT_TCP, -1, -1, title,
                "Retransmitowano %llu z %llu segmentów TCP zawierających dane (%s). "
                "Zaobserwowano również %llu zduplikowanych potwierdzeń (dup ACK), "
                "%llu segmentów poza kolejnością i %llu luk w numeracji sekwencyjnej "
                "(segmentów niezarejestrowanych w punkcie przechwytywania). Typowe przyczyny "
                "to utrata pakietów, przeciążenie łącza lub błędy warstwy fizycznej; "
                "w sprawnej sieci przewodowej udział retransmisji zwykle nie przekracza 1%%.",
                (unsigned long long)a->retrans_total,
                (unsigned long long)a->data_segs_total, pf,
                (unsigned long long)a->dupack_total, (unsigned long long)a->ooo_total,
                (unsigned long long)a->gaps_total);
        }
    }

    /* przepływy z dużym udziałem retransmisji */
    retr_t *cand = NULL;
    size_t nc = 0, capc = 0;
    for (size_t i = 0; i < a->flows.n; i++) {
        const flow_t *f = a->flows.list[i];
        if (f->key.proto != IPP_TCP)
            continue;
        uint32_t segs = f->data_segs[0] + f->data_segs[1];
        uint32_t retr = f->retrans[0] + f->retrans[1];
        if ((int)segs < c->flow_min_segs || retr == 0)
            continue;
        double rate = (double)retr / (double)segs;
        if (rate < c->flow_retrans_rate)
            continue;
        if (nc == capc) {
            capc = capc ? capc * 2 : 16;
            cand = xrealloc(cand, capc * sizeof *cand);
        }
        cand[nc].f = f;
        cand[nc].rate = rate;
        cand[nc].retr = retr;
        cand[nc].segs = segs;
        nc++;
    }
    if (nc) {
        qsort(cand, nc, sizeof *cand, cmp_retr);
        char list[1100] = "";
        for (size_t i = 0; i < nc && i < 5; i++) {
            char lbl[128], pf[16];
            flow_label(cand[i].f, lbl, sizeof lbl);
            fmt_percent(cand[i].rate, pf, sizeof pf);
            sappend(list, sizeof list, "\n• %s – %u retransmisji na %u segmentów (%s), "
                    "dup ACK: %u", lbl, cand[i].retr, cand[i].segs, pf,
                    cand[i].f->dupack[0] + cand[i].f->dupack[1]);
        }
        char title[200];
        snprintf(title, sizeof title, "Przepływy TCP z dużą liczbą retransmisji (%zu)", nc);
        analysis_add_anomaly(a, SEV_MEDIUM, CAT_TCP, -1, -1, title,
            "Wykryto %zu przepływów, w których co najmniej %.0f%% segmentów z danymi "
            "zostało retransmitowanych (uwzględniono przepływy z min. %d segmentami). "
            "Najbardziej dotknięte połączenia:%s",
            nc, c->flow_retrans_rate * 100.0, c->flow_min_segs, list);
    }
    free(cand);

    /* zerowe okno */
    if (a->zerowin_total > 0) {
        const flow_t *worst = NULL;
        uint32_t wz = 0;
        size_t nflows = 0;
        for (size_t i = 0; i < a->flows.n; i++) {
            const flow_t *f = a->flows.list[i];
            uint32_t z = f->zerowin[0] + f->zerowin[1];
            if (z) {
                nflows++;
                if (z > wz) {
                    wz = z;
                    worst = f;
                }
            }
        }
        char lbl[128] = "-";
        if (worst)
            flow_label(worst, lbl, sizeof lbl);
        analysis_add_anomaly(a, SEV_LOW, CAT_TCP, -1, -1,
            "Zerowe okno odbiorcze TCP (zero window)",
            "W %zu przepływach odnotowano %llu segmentów ogłaszających zerowe okno "
            "odbiorcze (najwięcej: %s – %u). Oznacza to, że aplikacja odbiorcy nie "
            "nadążała z odczytem danych z bufora i nadawca musiał wstrzymać transmisję; "
            "przyczyną jest zwykle przeciążenie hosta lub zbyt mały bufor gniazda.",
            nflows, (unsigned long long)a->zerowin_total, lbl, wz);
    }

    /* połączenia zrywane przez RST */
    if (a->tcp_established >= 10) {
        uint64_t reset = a->fc_count[FC_RESET];
        double ratio = (double)reset / (double)a->tcp_established;
        if (ratio >= c->rst_ratio) {
            char pf[16];
            fmt_percent(ratio, pf, sizeof pf);
            analysis_add_anomaly(a, SEV_LOW, CAT_TCP, -1, -1,
                "Wysoki udział połączeń zrywanych przez RST",
                "%llu z %llu nawiązanych połączeń TCP (%s) zakończyło się segmentem RST "
                "zamiast uporządkowanego zamknięcia FIN. Może to wynikać z przerywania "
                "połączeń przez zaporę lub IPS, awarii aplikacji, przekroczenia limitów "
                "czasu albo celowego zrywania sesji.",
                (unsigned long long)reset, (unsigned long long)a->tcp_established, pf);
        }
    }

    if (a->ooo_total > 0 && a->data_segs_total > 0) {
        char pf[16];
        fmt_percent((double)a->ooo_total / (double)a->data_segs_total, pf, sizeof pf);
        analysis_add_anomaly(a, SEV_INFO, CAT_TCP, -1, -1,
            "Segmenty TCP poza kolejnością",
            "Zarejestrowano %llu segmentów TCP dostarczonych poza kolejnością (%s segmentów "
            "z danymi). Niewielka liczba takich zdarzeń jest typowa dla sieci z wieloma "
            "ścieżkami (ECMP, agregacja łączy).",
            (unsigned long long)a->ooo_total, pf);
    }
}

/* ---------------- nieudane próby połączeń ---------------- */

static void detect_unanswered(analysis_t *a)
{
    if (has_category(a, CAT_RECON) || has_category(a, CAT_DOS))
        return;   /* już wyjaśnione przez skanowanie lub atak DoS */
    uint64_t un = a->fc_count[FC_UNANSWERED], rej = a->fc_count[FC_REJECTED];
    if ((int64_t)(un + rej) >= a->cfg.unanswered_min) {
        analysis_add_anomaly(a, SEV_LOW, CAT_TCP, -1, -1,
            "Nieudane próby nawiązania połączeń TCP",
            "%llu prób połączeń TCP pozostało bez odpowiedzi na SYN, a %llu zostało "
            "odrzuconych segmentem RST. Może to oznaczać niedostępne usługi, błędną "
            "konfigurację klientów, filtrowanie przez zaporę lub słabo nasilony rekonesans.",
            (unsigned long long)un, (unsigned long long)rej);
    }
}

/* ---------------- niedozwolone kombinacje flag TCP ---------------- */

static void detect_invalid_flags(analysis_t *a)
{
    static const char *const names[INV_COUNT] = {
        "NULL (brak flag)", "XMAS (FIN+PSH+URG)", "SYN+FIN", "SYN+RST", "FIN bez ACK"
    };
    static const char *const why[INV_COUNT] = {
        "Segmenty bez żadnej flagi są wykorzystywane w skanowaniu NULL (nmap -sN) do "
        "identyfikacji zamkniętych portów z pominięciem prostych filtrów.",
        "Kombinacja FIN+PSH+URG to sygnatura skanowania XMAS (nmap -sX).",
        "Jednoczesne SYN i FIN są sprzeczne; kombinacja służy do omijania zapór "
        "i identyfikacji systemu operacyjnego (fingerprinting).",
        "Jednoczesne SYN i RST są sprzeczne i wskazują na spreparowane pakiety.",
        "FIN bez ACK nie występuje w poprawnym połączeniu; typowy dla skanowania FIN "
        "(nmap -sF).",
    };
    for (int i = 0; i < INV_COUNT; i++) {
        if (!a->g.inv[i])
            continue;
        char s[IPSTR_LEN], d[IPSTR_LEN], title[200];
        ip_str(&a->g.inv_src[i], s, sizeof s);
        ip_str(&a->g.inv_dst[i], d, sizeof d);
        snprintf(title, sizeof title, "Niedozwolona kombinacja flag TCP: %s", names[i]);
        analysis_add_anomaly(a, (i <= INV_SYNFIN) ? SEV_HIGH : SEV_MEDIUM, CAT_PROTO,
            -1, -1, title,
            "Wykryto %llu segmentów TCP z kombinacją flag %s (pierwszy: %s → %s). %s",
            (unsigned long long)a->g.inv[i], names[i], s, d, why[i]);
    }
}

/* ---------------- DNS ---------------- */

static void detect_dns(analysis_t *a)
{
    const dns_stats_t *d = &a->dns;
    for (size_t i = 0; i < d->nsusp; i++) {
        const dns_susp_t *s = &d->susp[i];
        if ((int)s->count < a->cfg.dns_suspicious)
            continue;
        char src[IPSTR_LEN], title[200], dur[32];
        ip_str(&s->src, src, sizeof src);
        fmt_duration(s->last_ts - s->first_ts, dur, sizeof dur);
        snprintf(title, sizeof title, "Możliwe tunelowanie DNS z hosta %s", src);
        analysis_add_anomaly(a, SEV_HIGH, CAT_DNS, rel(a, s->first_ts), rel(a, s->last_ts),
            title,
            "Host %s wysłał %u zapytań DNS o nazwy z bardzo długimi lub losowo "
            "wyglądającymi etykietami (wysoka entropia znaków) w ciągu %s. Przykład: %s. "
            "W całym ruchu zapytania TXT stanowiły %llu z %llu zapytań. Kodowanie danych "
            "w nazwach domen jest techniką eksfiltracji danych i ukrytego kanału "
            "sterowania (np. iodine, dnscat2).",
            src, s->count, dur, s->example, (unsigned long long)d->qt_txt,
            (unsigned long long)d->queries);
    }
    if (d->responses >= 20 &&
        (double)d->nxdomain / (double)d->responses >= a->cfg.nxdomain_ratio) {
        char pf[16];
        fmt_percent((double)d->nxdomain / (double)d->responses, pf, sizeof pf);
        analysis_add_anomaly(a, SEV_MEDIUM, CAT_DNS, -1, -1,
            "Wysoki udział odpowiedzi DNS NXDOMAIN",
            "%llu z %llu odpowiedzi DNS (%s) informowało o nieistniejącej domenie. "
            "Duża liczba zapytań o nieistniejące domeny jest typowa dla złośliwego "
            "oprogramowania korzystającego z algorytmów generowania domen (DGA) "
            "lub dla błędnej konfiguracji.",
            (unsigned long long)d->nxdomain, (unsigned long long)d->responses, pf);
    }
}

/* ---------------- skoki natężenia ruchu ---------------- */

static void detect_spikes(analysis_t *a)
{
    const config_t *c = &a->cfg;
    size_t n;
    double w;
    ts_bin_t *b = ts_rebin(&a->ts, 1000000, 1.0, &n, &w);
    if (n < 10) {
        free(b);
        return;
    }
    double *v = xmalloc(n * sizeof *v), *s = xmalloc(n * sizeof *s);
    for (size_t i = 0; i < n; i++)
        v[i] = s[i] = (double)ts_bin_pkts(&b[i]) / w;

    /* Odporne statystyki: mediana i MAD (median absolute deviation) nie są
     * zaburzane przez same skoki, w przeciwieństwie do średniej i odchylenia. */
    qsort(s, n, sizeof *s, cmp_double_asc);
    double median = s[n / 2];
    for (size_t i = 0; i < n; i++)
        s[i] = fabs(v[i] - median);
    qsort(s, n, sizeof *s, cmp_double_asc);
    double mad = s[n / 2];
    free(s);

    double thr = median + c->spike_k * 1.4826 * mad;
    if (thr < 3.0 * median)
        thr = 3.0 * median;
    if (thr < c->spike_min_pps)
        thr = c->spike_min_pps;

    int events = 0;
    for (size_t i = 0; i < n;) {
        if (v[i] <= thr) {
            i++;
            continue;
        }
        size_t j = i;
        double peak = 0;
        ts_bin_t sum;
        memset(&sum, 0, sizeof sum);
        while (j < n && v[j] > thr) {
            if (v[j] > peak)
                peak = v[j];
            ts_bin_add(&sum, &b[j]);
            j++;
        }
        events++;
        if (events <= 5) {
            uint64_t tot = ts_bin_pkts(&sum);
            int dom = PC_TCP;
            for (int k = 1; k < PC_COUNT; k++)
                if (sum.pkts[k] > sum.pkts[dom])
                    dom = k;
            static const char *const pcn[PC_COUNT] = {"TCP", "UDP", "inne"};
            char pk[32], md[32], th[32], pf[16], title[200], t0s[32], t1s[32];
            fmt_compact(peak, pk, sizeof pk);
            fmt_compact(median, md, sizeof md);
            fmt_compact(thr, th, sizeof th);
            fmt_percent(tot ? (double)sum.pkts[dom] / (double)tot : 0, pf, sizeof pf);
            fmt_fixed((double)i * w, 0, t0s, sizeof t0s);
            fmt_fixed((double)j * w, 0, t1s, sizeof t1s);
            snprintf(title, sizeof title, "Gwałtowny wzrost natężenia ruchu (t = %s–%s s)",
                     t0s, t1s);
            analysis_add_anomaly(a, (j - i) >= 3 ? SEV_MEDIUM : SEV_LOW, CAT_VOLUME,
                (double)i * w, (double)j * w, title,
                "W przedziale %s–%s s od początku zapisu natężenie ruchu osiągnęło %s "
                "pakietów/s przy medianie %s pakietów/s (próg wykrycia: %s pakietów/s). "
                "Dominujący protokół w tym okresie: %s (%s pakietów). Gwałtowne skoki "
                "mogą wynikać z ataku wolumetrycznego, skanowania lub dużego transferu "
                "danych.",
                t0s, t1s, pk, md, th, pcn[dom], pf);
        }
        i = j;
    }
    if (events > 5)
        analysis_add_anomaly(a, SEV_INFO, CAT_VOLUME, -1, -1,
            "Kolejne skoki natężenia ruchu",
            "Pominięto %d dalszych przedziałów z natężeniem przekraczającym próg "
            "(raport przedstawia pierwsze 5).", events - 5);
    free(v);
    free(b);
}

/* ---------------- jakość danych wejściowych ---------------- */

static void detect_data_quality(analysis_t *a)
{
    const gstats_t *g = &a->g;
    if (a->read_warning[0])
        analysis_add_anomaly(a, SEV_LOW, CAT_QUALITY, -1, -1,
            "Plik pcap uszkodzony lub obcięty",
            "Odczyt pliku zakończył się błędem (%s). Raport obejmuje pakiety "
            "odczytane przed wystąpieniem błędu.", a->read_warning);
    if (g->unsupported)
        analysis_add_anomaly(a, SEV_INFO, CAT_QUALITY, -1, -1,
            "Nieobsługiwany typ warstwy łącza",
            "%llu pakietów ma typ łącza %s, którego narzędzie nie dekoduje; są one "
            "uwzględnione wyłącznie w statystykach ogólnych.",
            (unsigned long long)g->unsupported, a->datalink_name);
    if (g->truncated || g->malformed)
        analysis_add_anomaly(a, SEV_INFO, CAT_QUALITY, -1, -1,
            "Pakiety z niekompletnymi lub niespójnymi nagłówkami",
            "%llu pakietów ma nagłówki obcięte przez ograniczenie długości zapisu "
            "(snaplen), a %llu – niespójne pola (np. długość nagłówka). Pakiety te "
            "uwzględniono w statystykach wolumenu, ale nie w analizie przepływów.",
            (unsigned long long)g->truncated, (unsigned long long)g->malformed);
    if (g->bad_ipcksum)
        analysis_add_anomaly(a, SEV_INFO, CAT_QUALITY, -1, -1,
            "Błędne sumy kontrolne nagłówków IPv4",
            "%llu pakietów IPv4 ma niepoprawną sumę kontrolną nagłówka. Jeżeli ruch "
            "przechwycono na hoście nadawcy, przyczyną jest zwykle sprzętowe obliczanie "
            "sum kontrolnych (checksum offloading); w przeciwnym razie może to wskazywać "
            "na uszkodzenie danych lub spreparowane pakiety.",
            (unsigned long long)g->bad_ipcksum);
    if (g->frags) {
        uint64_t ip = g->ipv4 + g->ipv6;
        double r = ip ? (double)g->frags / (double)ip : 0;
        char pf[16];
        fmt_percent(r, pf, sizeof pf);
        analysis_add_anomaly(a, r > 0.01 ? SEV_LOW : SEV_INFO, CAT_PROTO, -1, -1,
            "Fragmentacja datagramów IP",
            "%llu pakietów (%s ruchu IP) to fragmenty datagramów IP. Fragmentacja "
            "obniża wydajność, a nietypowe fragmenty (bardzo małe, nakładające się) "
            "bywają używane do omijania systemów IDS.",
            (unsigned long long)g->frags, pf);
    }
    if (g->ts_backwards)
        analysis_add_anomaly(a, SEV_INFO, CAT_QUALITY, -1, -1,
            "Niemonotoniczne znaczniki czasu",
            "%llu pakietów ma znacznik czasu wcześniejszy niż pakiet poprzedzający. "
            "Zjawisko występuje przy łączeniu zapisów z wielu interfejsów; może "
            "nieznacznie zaburzać pomiary czasowe.",
            (unsigned long long)g->ts_backwards);
}

/* ---------------- uruchomienie ---------------- */

static int cmp_anomaly(const void *pa, const void *pb)
{
    const anomaly_t *x = pa, *y = pb;
    if (x->sev != y->sev)
        return x->sev > y->sev ? -1 : 1;
    return (x->seq > y->seq) - (x->seq < y->seq);
}

void anomaly_detect(analysis_t *a)
{
    size_t n;
    frec_t *r = build_recs(a, &n);

    detect_vertical_scan(a, r, n);
    detect_horizontal_scan(a, r, n);
    detect_floods(a, r, n);
    detect_invalid_flags(a);
    detect_dns(a);
    detect_beacons(a, r, n);
    detect_tcp_quality(a);
    detect_unanswered(a);
    detect_spikes(a);
    detect_data_quality(a);
    free(r);

    if (a->nanom > 1)
        qsort(a->anom, a->nanom, sizeof *a->anom, cmp_anomaly);
}
