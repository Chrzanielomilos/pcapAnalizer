/*
 * figures.c - przygotowanie danych i definicji wykresów.
 */
#include "figures.h"

#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* Kolory "miar" (np. pakiety/bajty, wysłane/odebrane) - inne niż kolory
 * protokołów, aby kolor zawsze oznaczał tę samą kategorię. */
#define COL_M1 0x6250d6
#define COL_M2 0xeda100

/* ======================= pamięć zestawu ======================= */

static void *fs_alloc(figure_set_t *fs, size_t n)
{
    void *p = xcalloc(1, n ? n : 1);
    if (fs->nalloc == fs->capalloc) {
        fs->capalloc = fs->capalloc ? fs->capalloc * 2 : 64;
        fs->allocs = xrealloc(fs->allocs, fs->capalloc * sizeof *fs->allocs);
    }
    fs->allocs[fs->nalloc++] = p;
    return p;
}

static double *fs_dbl(figure_set_t *fs, size_t n)
{
    return fs_alloc(fs, (n ? n : 1) * sizeof(double));
}

static const char **fs_strv(figure_set_t *fs, size_t n)
{
    return fs_alloc(fs, (n ? n : 1) * sizeof(const char *));
}

static __attribute__((format(printf, 2, 3)))
char *fs_printf(figure_set_t *fs, const char *fmt, ...)
{
    char tmp[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    char *s = fs_alloc(fs, strlen(tmp) + 1);
    memcpy(s, tmp, strlen(tmp) + 1);
    return s;
}

void figures_free(figure_set_t *fs)
{
    for (size_t i = 0; i < fs->nalloc; i++)
        free(fs->allocs[i]);
    free(fs->allocs);
    memset(fs, 0, sizeof *fs);
}

static void add_series(chart_t *c, const char *name, const double *x, const double *y,
                       int n, uint32_t color)
{
    if (c->nseries >= CHART_MAX_SERIES)
        return;
    chart_series_t *s = &c->series[c->nseries++];
    s->name = name;
    s->x = x;
    s->y = y;
    s->n = n;
    s->color = color;
}

/* ======================= szeregi czasowe ======================= */

static void build_timeseries(figure_set_t *fs, const analysis_t *a)
{
    size_t nb;
    double bw;
    ts_bin_t *bins = ts_rebin(&a->ts, 300, 0.0, &nb, &bw);
    fs->bin_width = bw;
    char bwt[32];
    fmt_duration(bw, bwt, sizeof bwt);

    double *x = fs_dbl(fs, nb);
    double *thr[PC_COUNT], *pps[PC_COUNT];
    for (int p = 0; p < PC_COUNT; p++) {
        thr[p] = fs_dbl(fs, nb);
        pps[p] = fs_dbl(fs, nb);
    }
    double *syn = fs_dbl(fs, nb), *synack = fs_dbl(fs, nb);
    double *retr = fs_dbl(fs, nb), *dup = fs_dbl(fs, nb);
    double *zw = fs_dbl(fs, nb), *rst = fs_dbl(fs, nb);
    for (size_t i = 0; i < nb; i++) {
        x[i] = ((double)i + 0.5) * bw;
        for (int p = 0; p < PC_COUNT; p++) {
            thr[p][i] = (double)bins[i].bytes[p] * 8.0 / bw;
            pps[p][i] = (double)bins[i].pkts[p] / bw;
        }
        syn[i] = bins[i].syn / bw;
        synack[i] = bins[i].synack / bw;
        retr[i] = bins[i].retrans / bw;
        dup[i] = bins[i].dupack / bw;
        zw[i] = bins[i].zerowin / bw;
        rst[i] = bins[i].rst / bw;
    }
    free(bins);

    int has_other = (a->g.pb_pkts[PB_ICMP] + a->g.pb_pkts[PB_OTHERIP] +
                     a->g.pb_pkts[PB_NONIP]) > 0;
    int n = (int)nb;

    figure_t *f = &fs->fig[FIG_THROUGHPUT];
    snprintf(f->file, sizeof f->file, "01_przeplywnosc.png");
    f->chart.type = CH_LINE;
    f->chart.title = "Przepływność w czasie";
    f->chart.subtitle = fs_printf(fs, "Bity na sekundę wg protokołu, przedział agregacji %s", bwt);
    f->chart.xlabel = "Czas od początku zapisu [s]";
    f->chart.yfmt = VF_BITRATE;
    add_series(&f->chart, "TCP", x, thr[PC_TCP], n, COL_TCP);
    add_series(&f->chart, "UDP", x, thr[PC_UDP], n, COL_UDP);
    if (has_other)
        add_series(&f->chart, "Inne", x, thr[PC_OTHER], n, COL_OTHER);
    f->caption = "Przepływność ruchu w funkcji czasu";
    f->desc = fs_printf(fs,
        "Wykres przedstawia przepływność (liczbę bitów na sekundę, liczoną z pełnej "
        "długości ramek) w kolejnych przedziałach czasu o szerokości %s, osobno dla TCP, "
        "UDP i pozostałych protokołów. Pozwala ocenić obciążenie łącza, zidentyfikować "
        "okresy wzmożonej aktywności oraz udział protokołów w czasie. Gwałtowne, "
        "krótkotrwałe skoki mogą odpowiadać atakom wolumetrycznym lub dużym transferom.", bwt);

    f = &fs->fig[FIG_PPS];
    snprintf(f->file, sizeof f->file, "02_natezenie_pakietow.png");
    f->chart.type = CH_LINE;
    f->chart.title = "Natężenie ruchu";
    f->chart.subtitle = fs_printf(fs, "Pakiety na sekundę wg protokołu, przedział agregacji %s", bwt);
    f->chart.xlabel = "Czas od początku zapisu [s]";
    f->chart.yfmt = VF_NUM;
    add_series(&f->chart, "TCP", x, pps[PC_TCP], n, COL_TCP);
    add_series(&f->chart, "UDP", x, pps[PC_UDP], n, COL_UDP);
    if (has_other)
        add_series(&f->chart, "Inne", x, pps[PC_OTHER], n, COL_OTHER);
    f->caption = "Natężenie ruchu (pakiety na sekundę) w funkcji czasu";
    f->desc =
        "Liczba pakietów na sekundę w tych samych przedziałach czasu co wykres przepływności. "
        "Zestawienie obu wykresów ujawnia charakter ruchu: wysoki poziom pakietów przy niskiej "
        "przepływności oznacza wiele małych pakietów (typowe dla skanowania, ataków SYN flood "
        "i ruchu sterującego), a wysoka przepływność przy umiarkowanej liczbie pakietów – "
        "transfer dużych porcji danych.";

    f = &fs->fig[FIG_HANDSHAKE];
    snprintf(f->file, sizeof f->file, "11_uzgadnianie_syn.png");
    f->chart.type = CH_LINE;
    f->chart.title = "Inicjowanie połączeń TCP";
    f->chart.subtitle = fs_printf(fs, "Segmenty SYN i SYN-ACK na sekundę, przedział %s", bwt);
    f->chart.xlabel = "Czas od początku zapisu [s]";
    f->chart.yfmt = VF_NUM;
    add_series(&f->chart, "SYN", x, syn, n, CHART_PALETTE[0]);
    add_series(&f->chart, "SYN-ACK", x, synack, n, CHART_PALETTE[1]);
    f->caption = "Segmenty SYN i SYN-ACK w funkcji czasu";
    f->desc =
        "Porównanie liczby żądań nawiązania połączenia (SYN) i odpowiedzi serwerów (SYN-ACK). "
        "W prawidłowym ruchu obie linie przebiegają blisko siebie. Trwała przewaga SYN nad "
        "SYN-ACK oznacza połączenia bez odpowiedzi – typowy obraz skanowania portów, "
        "ataku SYN flood lub niedostępności usług.";

    f = &fs->fig[FIG_TCPHEALTH];
    snprintf(f->file, sizeof f->file, "12_problemy_tcp.png");
    f->chart.type = CH_LINE;
    f->chart.title = "Zdarzenia świadczące o problemach TCP";
    f->chart.subtitle = fs_printf(fs, "Liczba zdarzeń na sekundę, przedział %s", bwt);
    f->chart.xlabel = "Czas od początku zapisu [s]";
    f->chart.yfmt = VF_NUM;
    add_series(&f->chart, "Retransmisje", x, retr, n, CHART_PALETTE[0]);
    add_series(&f->chart, "Dup ACK", x, dup, n, CHART_PALETTE[1]);
    add_series(&f->chart, "Zerowe okno", x, zw, n, CHART_PALETTE[2]);
    add_series(&f->chart, "RST", x, rst, n, CHART_PALETTE[3]);
    f->caption = "Retransmisje, zduplikowane ACK, zerowe okna i segmenty RST w czasie";
    f->desc =
        "Rozkład w czasie zdarzeń wskazujących na problemy z dostarczaniem danych: "
        "retransmisji segmentów, zduplikowanych potwierdzeń (sygnał utraty segmentu dla "
        "nadawcy), ogłoszeń zerowego okna odbiorczego (przeciążony odbiorca) oraz segmentów "
        "RST (zrywanie lub odrzucanie połączeń). Skupienie zdarzeń w krótkim okresie "
        "wskazuje na chwilowe przeciążenie lub awarię, a równomierny rozkład – na problem "
        "stały, np. uszkodzone łącze.";
}

/* ======================= protokoły i rozmiary ======================= */

static void build_proto(figure_set_t *fs, const analysis_t *a)
{
    static const char *const names[PB_COUNT] = {"TCP", "UDP", "ICMP", "Inne IP", "Nie-IP"};
    const char **cats = fs_strv(fs, PB_COUNT);
    double *vp = fs_dbl(fs, PB_COUNT), *vb = fs_dbl(fs, PB_COUNT);
    int n = 0;
    for (int i = 0; i < PB_COUNT; i++) {
        if (i > PB_UDP && a->g.pb_pkts[i] == 0)
            continue;
        cats[n] = names[i];
        vp[n] = a->g.pkts ? (double)a->g.pb_pkts[i] / (double)a->g.pkts : 0;
        vb[n] = a->g.bytes ? (double)a->g.pb_bytes[i] / (double)a->g.bytes : 0;
        n++;
    }
    figure_t *f = &fs->fig[FIG_PROTO];
    snprintf(f->file, sizeof f->file, "03_protokoly.png");
    f->chart.type = CH_BAR;
    f->chart.title = "Udział protokołów w ruchu";
    f->chart.subtitle = "Procent wszystkich pakietów i bajtów";
    f->chart.yfmt = VF_PERCENT;
    f->chart.categories = cats;
    f->chart.ncat = n;
    add_series(&f->chart, "Udział w pakietach", NULL, vp, n, COL_M1);
    add_series(&f->chart, "Udział w bajtach", NULL, vb, n, COL_M2);
    f->caption = "Udział protokołów w liczbie pakietów i wolumenie";
    f->desc =
        "Procentowy udział protokołów warstwy transportowej w łącznej liczbie pakietów "
        "i w łącznym wolumenie danych. Różnica między słupkami informuje o typowym rozmiarze "
        "pakietów danego protokołu: protokół z większym udziałem w bajtach niż w pakietach "
        "przenosi duże porcje danych (np. transfery TCP), a odwrotnie – głównie małe "
        "komunikaty (np. DNS, sterowanie). Kategoria „Nie-IP” obejmuje m.in. ARP i LLDP.";

    const char **scats = fs_strv(fs, SIZE_BINS);
    double *sv[PC_COUNT];
    for (int p = 0; p < PC_COUNT; p++)
        sv[p] = fs_dbl(fs, SIZE_BINS);
    for (int i = 0; i < SIZE_BINS; i++) {
        scats[i] = SIZE_BIN_LABELS[i];
        for (int p = 0; p < PC_COUNT; p++)
            sv[p][i] = (double)a->g.size_hist[p][i];
    }
    uint64_t other = 0;
    for (int i = 0; i < SIZE_BINS; i++)
        other += a->g.size_hist[PC_OTHER][i];

    f = &fs->fig[FIG_SIZES];
    snprintf(f->file, sizeof f->file, "04_rozmiary_pakietow.png");
    f->chart.type = CH_BAR;
    f->chart.title = "Rozkład rozmiarów pakietów";
    f->chart.subtitle = "Liczba pakietów w przedziałach długości ramki";
    f->chart.xlabel = "Długość ramki [B]";
    f->chart.yfmt = VF_NUM;
    f->chart.categories = scats;
    f->chart.ncat = SIZE_BINS;
    add_series(&f->chart, "TCP", NULL, sv[PC_TCP], SIZE_BINS, COL_TCP);
    add_series(&f->chart, "UDP", NULL, sv[PC_UDP], SIZE_BINS, COL_UDP);
    if (other)
        add_series(&f->chart, "Inne", NULL, sv[PC_OTHER], SIZE_BINS, COL_OTHER);
    f->caption = "Histogram długości ramek wg protokołu";
    f->desc =
        "Histogram długości ramek (z nagłówkiem warstwy łącza, bez sumy FCS) w przedziałach "
        "o granicach będących potęgami dwójki. Ruch TCP ma zwykle rozkład dwumodalny: małe "
        "segmenty potwierdzeń (do 64–127 B) i pełne segmenty danych bliskie MTU (1024–1518 B). "
        "Przewaga bardzo małych pakietów przy braku dużych może wskazywać na skanowanie "
        "lub atak SYN flood, a ramki ≥1519 B – na odciążanie segmentacji (TSO/GRO) lub "
        "ramki jumbo.";
}

/* ======================= hosty i usługi ======================= */

typedef struct {
    size_t   idx;
    uint64_t key;
} rank_t;

static int cmp_rank(const void *pa, const void *pb)
{
    const rank_t *x = pa, *y = pb;
    if (x->key != y->key)
        return x->key > y->key ? -1 : 1;
    return (x->idx > y->idx) - (x->idx < y->idx);
}

static void build_hosts(figure_set_t *fs, const analysis_t *a)
{
    int topn = a->cfg.top_n;
    size_t nh = a->hosts.n;
    rank_t *rk = xmalloc((nh ? nh : 1) * sizeof *rk);
    for (size_t i = 0; i < nh; i++) {
        rk[i].idx = i;
        rk[i].key = a->hosts.items[i].bytes_out + a->hosts.items[i].bytes_in;
    }
    qsort(rk, nh, sizeof *rk, cmp_rank);
    int n = (int)PA_MIN(nh, (size_t)topn);
    const char **cats = fs_strv(fs, (size_t)n);
    double *out = fs_dbl(fs, (size_t)n), *in = fs_dbl(fs, (size_t)n);
    for (int i = 0; i < n; i++) {
        const host_t *h = &a->hosts.items[rk[i].idx];
        char ip[IPSTR_LEN];
        cats[i] = fs_printf(fs, "%s", ip_str(&h->ip, ip, sizeof ip));
        out[i] = (double)h->bytes_out;
        in[i] = (double)h->bytes_in;
    }
    free(rk);

    figure_t *f = &fs->fig[FIG_TALKERS];
    snprintf(f->file, sizeof f->file, "05_najaktywniejsze_hosty.png");
    f->chart.type = CH_HBAR;
    f->chart.title = fs_printf(fs, "Najaktywniejsze hosty (top %d)", topn);
    f->chart.subtitle = "Wolumen danych wysłanych i odebranych przez host";
    f->chart.yfmt = VF_BYTES;
    f->chart.value_labels = 1;
    f->chart.categories = cats;
    f->chart.ncat = n;
    add_series(&f->chart, "Wysłane", NULL, out, n, COL_M1);
    add_series(&f->chart, "Odebrane", NULL, in, n, COL_M2);
    f->caption = "Hosty generujące największy wolumen ruchu";
    f->desc =
        "Ranking adresów IP według łącznego wolumenu ruchu (suma długości ramek wysłanych "
        "i odebranych). Proporcja części „wysłane” i „odebrane” wskazuje rolę hosta: "
        "serwery i źródła transferów mają przewagę danych wysłanych, a klienci pobierający "
        "dane – odebranych. Host o dużym wolumenie danych wysłanych na zewnątrz sieci "
        "lokalnej może wymagać sprawdzenia pod kątem eksfiltracji danych.";

    /* --- usługi (port strony odpowiadającej) --- */
    uint64_t *bytes = xcalloc(2 * 65536, sizeof *bytes);
    uint64_t *flows = xcalloc(2 * 65536, sizeof *flows);
    for (size_t i = 0; i < a->flows.n; i++) {
        const flow_t *fl = a->flows.list[i];
        size_t k = (fl->key.proto == IPP_UDP ? 65536u : 0u) + flow_sport(fl);
        bytes[k] += fl->bytes[0] + fl->bytes[1];
        flows[k]++;
    }
    size_t nc = 0;
    for (size_t k = 0; k < 2 * 65536; k++)
        if (flows[k])
            nc++;
    rank_t *sr = xmalloc((nc ? nc : 1) * sizeof *sr);
    nc = 0;
    for (size_t k = 0; k < 2 * 65536; k++)
        if (flows[k]) {
            sr[nc].idx = k;
            sr[nc].key = bytes[k];
            nc++;
        }
    qsort(sr, nc, sizeof *sr, cmp_rank);
    n = (int)PA_MIN(nc, (size_t)topn);
    const char **sc = fs_strv(fs, (size_t)n);
    double *vt = fs_dbl(fs, (size_t)n), *vu = fs_dbl(fs, (size_t)n);
    for (int i = 0; i < n; i++) {
        size_t k = sr[i].idx;
        int udp = k >= 65536;
        char svc[64];
        fmt_service(udp ? IPP_UDP : IPP_TCP, (uint16_t)(k & 0xFFFF), svc, sizeof svc);
        sc[i] = fs_printf(fs, "%s · %llu przepł.", svc, (unsigned long long)flows[k]);
        (udp ? vu : vt)[i] = (double)bytes[k];
    }
    free(sr);
    free(bytes);
    free(flows);

    f = &fs->fig[FIG_SERVICES];
    snprintf(f->file, sizeof f->file, "06_uslugi.png");
    f->chart.type = CH_HBAR;
    f->chart.title = fs_printf(fs, "Najważniejsze usługi (top %d)", topn);
    f->chart.subtitle = "Wolumen ruchu wg protokołu i portu usługi (strony odpowiadającej)";
    f->chart.yfmt = VF_BYTES;
    f->chart.value_labels = 1;
    f->chart.categories = sc;
    f->chart.ncat = n;
    add_series(&f->chart, "TCP", NULL, vt, n, COL_TCP);
    add_series(&f->chart, "UDP", NULL, vu, n, COL_UDP);
    f->caption = "Usługi o największym wolumenie ruchu";
    f->desc =
        "Usługi identyfikowane parą protokół/port strony odpowiadającej (serwera), "
        "uszeregowane według wolumenu ruchu w obu kierunkach; przy każdej podano liczbę "
        "przepływów. Nazwy usług przypisano na podstawie numerów portów (bez inspekcji "
        "treści), więc usługa działająca na niestandardowym porcie nie zostanie nazwana. "
        "Nietypowe porty o dużym wolumenie warto zweryfikować.";
}

/* ======================= przepływy ======================= */

static void build_flows(figure_set_t *fs, const analysis_t *a)
{
    const char **cats = fs_strv(fs, FC_COUNT);
    double *vt = fs_dbl(fs, FC_COUNT), *vu = fs_dbl(fs, FC_COUNT);
    int n = 0;
    for (int c = 0; c < FC_COUNT; c++) {
        if (!a->fc_count[c])
            continue;
        cats[n] = flow_class_name((flow_class_t)c);
        if (c >= FC_UDP_BIDIR)
            vu[n] = (double)a->fc_count[c];
        else
            vt[n] = (double)a->fc_count[c];
        n++;
    }
    figure_t *f = &fs->fig[FIG_FLOWSTATES];
    snprintf(f->file, sizeof f->file, "07_stany_przeplywow.png");
    f->chart.type = CH_HBAR;
    f->chart.title = "Klasyfikacja przepływów";
    f->chart.subtitle = "Liczba przepływów wg stanu na końcu zapisu";
    f->chart.yfmt = VF_NUM;
    f->chart.value_labels = 1;
    f->chart.categories = cats;
    f->chart.ncat = n;
    add_series(&f->chart, "TCP", NULL, vt, n, COL_TCP);
    add_series(&f->chart, "UDP", NULL, vu, n, COL_UDP);
    f->caption = "Przepływy wg stanu połączenia";
    f->desc =
        "Klasyfikacja przepływów na podstawie przebiegu uzgadniania i zamykania połączeń TCP "
        "oraz kierunkowości ruchu UDP. W zdrowym ruchu dominują połączenia zakończone (FIN) "
        "i aktywne. Duża liczba połączeń bez odpowiedzi lub odrzuconych (RST na SYN) "
        "wskazuje na skanowanie albo niedostępne usługi, połączeń półotwartych – na atak "
        "SYN flood, a jednokierunkowych przepływów UDP – na skanowanie UDP, zalewanie "
        "lub ruch rozgłoszeniowy.";

    /* --- wykres punktowy: czas trwania vs wolumen --- */
    size_t ntcp = 0, nudp = 0;
    for (size_t i = 0; i < a->flows.n; i++) {
        if (a->flows.list[i]->key.proto == IPP_TCP)
            ntcp++;
        else
            nudp++;
    }
    const size_t limit = 5000;
    size_t st = ntcp > limit ? ntcp / limit + 1 : 1;
    size_t su = nudp > limit ? nudp / limit + 1 : 1;
    double *tx = fs_dbl(fs, ntcp / st + 1), *ty = fs_dbl(fs, ntcp / st + 1);
    double *ux = fs_dbl(fs, nudp / su + 1), *uy = fs_dbl(fs, nudp / su + 1);
    size_t it = 0, iu = 0, kt = 0, ku = 0;
    for (size_t i = 0; i < a->flows.n; i++) {
        const flow_t *fl = a->flows.list[i];
        double d = PA_MAX(fl->last_ts - fl->first_ts, 1e-4);
        double b = PA_MAX((double)(fl->bytes[0] + fl->bytes[1]), 1.0);
        if (fl->key.proto == IPP_TCP) {
            if (kt++ % st == 0) {
                tx[it] = d;
                ty[it] = b;
                it++;
            }
        } else if (ku++ % su == 0) {
            ux[iu] = d;
            uy[iu] = b;
            iu++;
        }
    }
    f = &fs->fig[FIG_SCATTER];
    snprintf(f->file, sizeof f->file, "08_przeplywy_czas_wolumen.png");
    f->chart.type = CH_SCATTER;
    f->chart.title = "Czas trwania a wolumen przepływów";
    f->chart.subtitle = (st > 1 || su > 1)
        ? "Każdy punkt to jeden przepływ (próbka); skale logarytmiczne"
        : "Każdy punkt to jeden przepływ; skale logarytmiczne";
    f->chart.xlabel = "Czas trwania przepływu";
    f->chart.xfmt = VF_SECONDS;
    f->chart.yfmt = VF_BYTES;
    f->chart.log_x = f->chart.log_y = 1;
    add_series(&f->chart, "TCP", tx, ty, (int)it, COL_TCP);
    add_series(&f->chart, "UDP", ux, uy, (int)iu, COL_UDP);
    f->caption = "Rozkład przepływów: czas trwania i wolumen";
    f->desc =
        "Każdy punkt odpowiada jednemu przepływowi (czas trwania na osi poziomej, łączny "
        "wolumen w obu kierunkach na osi pionowej, skale logarytmiczne; czasy krótsze niż "
        "0,1 ms przedstawiono jako 0,1 ms). Typowe grupy to: krótkie wymiany zapytanie–"
        "odpowiedź (lewy dolny róg), długie sesje interaktywne o małym wolumenie (prawy "
        "dolny róg) i transfery masowe (góra wykresu). Gęste skupisko identycznych, "
        "jednopakietowych przepływów wskazuje na skanowanie lub zalewanie.";

    /* --- histogram RTT uzgadniania --- */
    static const char *const rcat[] = {"<1", "1–5", "5–10", "10–25", "25–50",
                                       "50–100", "100–250", "250–500", "≥500"};
    static const double edges[] = {1, 5, 10, 25, 50, 100, 250, 500};
    const int nr = (int)ARRAY_LEN(rcat);
    const char **rc = fs_strv(fs, (size_t)nr);
    double *rv = fs_dbl(fs, (size_t)nr);
    for (int i = 0; i < nr; i++)
        rc[i] = rcat[i];
    for (size_t i = 0; i < a->nrtt; i++) {
        double ms = a->rtts[i] * 1000.0;
        int b = 0;
        while (b < (int)ARRAY_LEN(edges) && ms >= edges[b])
            b++;
        rv[b] += 1;
    }
    f = &fs->fig[FIG_RTT];
    snprintf(f->file, sizeof f->file, "09_rtt_uzgadniania.png");
    f->chart.type = CH_BAR;
    f->chart.title = "Czas uzgadniania połączeń TCP";
    f->chart.subtitle = fs_printf(fs, "Liczba połączeń wg czasu SYN → ACK (n = %zu)", a->nrtt);
    f->chart.xlabel = "Czas uzgadniania [ms]";
    f->chart.yfmt = VF_NUM;
    f->chart.categories = rc;
    f->chart.ncat = nr;
    add_series(&f->chart, "Połączenia", NULL, rv, nr, COL_TCP);
    f->caption = "Rozkład czasu uzgadniania trójetapowego TCP";
    f->desc =
        "Rozkład czasu od segmentu SYN do końcowego ACK uzgadniania trójetapowego dla "
        "połączeń, w których zaobserwowano wszystkie trzy segmenty. Przy przechwytywaniu "
        "ruchu po stronie klienta wartość ta przybliża czas podróży w obie strony (RTT) do "
        "serwera wraz z czasem reakcji jego stosu TCP. Rozkład wielomodalny odzwierciedla "
        "grupy serwerów o różnej odległości sieciowej, a pojedyncze bardzo duże wartości – "
        "retransmisje SYN lub przeciążone serwery.";
}

/* ======================= flagi TCP ======================= */

static void build_flags(figure_set_t *fs, const analysis_t *a)
{
    static const char *const cats[] = {"SYN", "SYN+ACK", "ACK*", "PSH", "FIN",
                                       "RST", "URG", "ECE", "CWR"};
    const int n = (int)ARRAY_LEN(cats);
    double *v = fs_dbl(fs, (size_t)n);
    v[0] = (double)a->g.syn_only;
    v[1] = (double)a->g.synack;
    v[2] = (double)a->g.pure_ack;
    v[3] = (double)a->g.psh_pkts;
    v[4] = (double)a->g.fin_pkts;
    v[5] = (double)a->g.rst_pkts;
    v[6] = (double)a->g.flag_bits[5];
    v[7] = (double)a->g.flag_bits[6];
    v[8] = (double)a->g.flag_bits[7];
    const char **c = fs_strv(fs, (size_t)n);
    for (int i = 0; i < n; i++)
        c[i] = cats[i];

    figure_t *f = &fs->fig[FIG_FLAGS];
    snprintf(f->file, sizeof f->file, "10_flagi_tcp.png");
    f->chart.type = CH_BAR;
    f->chart.title = "Flagi TCP";
    f->chart.subtitle = "Liczba segmentów z daną flagą (ACK* = czyste potwierdzenia bez danych)";
    f->chart.yfmt = VF_NUM;
    f->chart.categories = c;
    f->chart.ncat = n;
    add_series(&f->chart, "Segmenty", NULL, v, n, COL_TCP);
    f->caption = "Liczba segmentów TCP wg flag";
    f->desc =
        "Liczność segmentów TCP z poszczególnymi flagami: SYN (żądanie połączenia, bez ACK), "
        "SYN+ACK (odpowiedź serwera), ACK* (potwierdzenie bez danych), PSH (dane do "
        "natychmiastowego przekazania aplikacji), FIN (zamknięcie), RST (zerwanie lub "
        "odrzucenie), URG (dane pilne) oraz ECE/CWR (jawne powiadamianie o przeciążeniu, "
        "ECN). W prawidłowym ruchu liczba SYN jest zbliżona do SYN+ACK i FIN; przewaga SYN "
        "lub RST jest charakterystyczna dla skanowania i ataków.";
}

/* ======================= API ======================= */

void figures_build(figure_set_t *fs, const analysis_t *a)
{
    memset(fs, 0, sizeof *fs);
    build_timeseries(fs, a);
    build_proto(fs, a);
    build_hosts(fs, a);
    build_flows(fs, a);
    build_flags(fs, a);
}

int figures_write_png(const figure_set_t *fs, const char *dir, int verbose)
{
    int errors = 0;
    for (int i = 0; i < FIG_COUNT; i++) {
        char path[4096];
        snprintf(path, sizeof path, "%s/%s", dir, fs->fig[i].file);
        if (chart_write_png(&fs->fig[i].chart, path, 2.0) != 0) {
            fprintf(stderr, PA_NAME ": nie udało się zapisać %s\n", path);
            errors++;
        } else if (verbose) {
            printf("  wykres: %s\n", path);
        }
    }
    return errors ? -1 : 0;
}
