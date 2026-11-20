/*
 * stats.c - implementacja agregatorów statystyk.
 */
#include "stats.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

/* ======================= szeregi czasowe ======================= */

void ts_init(timeseries_t *ts, double initial_width)
{
    memset(ts, 0, sizeof *ts);
    ts->width = initial_width;
    ts->bins = xcalloc(TS_MAX_BINS, sizeof *ts->bins);
}

void ts_free(timeseries_t *ts)
{
    free(ts->bins);
    memset(ts, 0, sizeof *ts);
}

void ts_bin_add(ts_bin_t *d, const ts_bin_t *s)
{
    for (int i = 0; i < PC_COUNT; i++) {
        d->pkts[i] += s->pkts[i];
        d->bytes[i] += s->bytes[i];
    }
    d->syn += s->syn;
    d->synack += s->synack;
    d->rst += s->rst;
    d->retrans += s->retrans;
    d->dupack += s->dupack;
    d->zerowin += s->zerowin;
    d->ooo += s->ooo;
    d->newflows += s->newflows;
}

uint64_t ts_bin_pkts(const ts_bin_t *b)
{
    return b->pkts[PC_TCP] + b->pkts[PC_UDP] + b->pkts[PC_OTHER];
}

ts_bin_t *ts_bin(timeseries_t *ts, double t)
{
    if (!ts->started) {
        ts->started = 1;
        ts->t0 = t;
    }
    double rel = t - ts->t0;
    if (rel < 0)
        rel = 0;           /* pakiety z cofniętym znacznikiem czasu */

    while (rel / ts->width >= (double)TS_MAX_BINS) {
        size_t half = (ts->n + 1) / 2;
        for (size_t i = 0; i < half; i++) {
            ts_bin_t m = ts->bins[2 * i];
            if (2 * i + 1 < ts->n)
                ts_bin_add(&m, &ts->bins[2 * i + 1]);
            ts->bins[i] = m;
        }
        memset(&ts->bins[half], 0, (TS_MAX_BINS - half) * sizeof(ts_bin_t));
        ts->n = half;
        ts->width *= 2.0;
    }
    size_t idx = (size_t)(rel / ts->width);
    if (idx >= TS_MAX_BINS)
        idx = TS_MAX_BINS - 1;
    if (idx + 1 > ts->n)
        ts->n = idx + 1;
    return &ts->bins[idx];
}

ts_bin_t *ts_rebin(const timeseries_t *ts, size_t max_bins, double min_width,
                   size_t *n_out, double *w_out)
{
    size_t f = 1;
    if (ts->width > 0 && min_width > ts->width)
        f = (size_t)ceil(min_width / ts->width - 1e-9);
    if (max_bins < 1)
        max_bins = 1;
    while ((ts->n + f - 1) / f > max_bins)
        f++;
    size_t n = ts->n ? (ts->n + f - 1) / f : 0;
    ts_bin_t *out = xcalloc(n ? n : 1, sizeof *out);
    for (size_t i = 0; i < ts->n; i++)
        ts_bin_add(&out[i / f], &ts->bins[i]);
    *n_out = n;
    *w_out = ts->width * (double)f;
    return out;
}

/* ======================= hosty ======================= */

void host_table_init(host_table_t *t)
{
    memset(t, 0, sizeof *t);
    t->cap = 256;
    t->items = xmalloc(t->cap * sizeof *t->items);
    t->next = xmalloc(t->cap * sizeof *t->next);
    t->nbuckets = 512;
    t->buckets = xmalloc(t->nbuckets * sizeof *t->buckets);
    for (size_t i = 0; i < t->nbuckets; i++)
        t->buckets[i] = -1;
}

void host_table_free(host_table_t *t)
{
    free(t->items);
    free(t->next);
    free(t->buckets);
    memset(t, 0, sizeof *t);
}

static uint32_t ip_hash(const ip_addr_t *ip)
{
    return fnv1a(ip, sizeof *ip);
}

static void host_rehash(host_table_t *t)
{
    free(t->buckets);
    t->nbuckets *= 2;
    t->buckets = xmalloc(t->nbuckets * sizeof *t->buckets);
    for (size_t i = 0; i < t->nbuckets; i++)
        t->buckets[i] = -1;
    for (size_t i = 0; i < t->n; i++) {
        uint32_t h = ip_hash(&t->items[i].ip) & (uint32_t)(t->nbuckets - 1);
        t->next[i] = t->buckets[h];
        t->buckets[h] = (int32_t)i;
    }
}

host_t *host_get(host_table_t *t, const ip_addr_t *ip)
{
    uint32_t h = ip_hash(ip) & (uint32_t)(t->nbuckets - 1);
    for (int32_t i = t->buckets[h]; i >= 0; i = t->next[i])
        if (ip_cmp(&t->items[i].ip, ip) == 0)
            return &t->items[i];

    if (t->n == t->cap) {
        t->cap *= 2;
        t->items = xrealloc(t->items, t->cap * sizeof *t->items);
        t->next = xrealloc(t->next, t->cap * sizeof *t->next);
    }
    if (t->n + 1 > t->nbuckets * 2) {
        host_rehash(t);
        h = ip_hash(ip) & (uint32_t)(t->nbuckets - 1);
    }
    int32_t i = (int32_t)t->n++;
    memset(&t->items[i], 0, sizeof t->items[i]);
    t->items[i].ip = *ip;
    t->next[i] = t->buckets[h];
    t->buckets[h] = i;
    return &t->items[i];
}

/* ======================= rozmiary pakietów ======================= */

const char *const SIZE_BIN_LABELS[SIZE_BINS] = {
    "<64", "64–127", "128–255", "256–511", "512–1023", "1024–1518", "≥1519"
};

int size_bin(uint32_t len)
{
    if (len < 64)   return 0;
    if (len < 128)  return 1;
    if (len < 256)  return 2;
    if (len < 512)  return 3;
    if (len < 1024) return 4;
    if (len < 1519) return 5;
    return 6;
}

/* ======================= DNS ======================= */

double shannon_entropy(const char *s, size_t n)
{
    if (n == 0)
        return 0.0;
    unsigned cnt[256] = {0};
    for (size_t i = 0; i < n; i++)
        cnt[(unsigned char)s[i]]++;
    double h = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!cnt[i])
            continue;
        double p = (double)cnt[i] / (double)n;
        h -= p * log2(p);
    }
    return h;
}

void dns_free(dns_stats_t *d)
{
    free(d->susp);
    memset(d, 0, sizeof *d);
}

static void dns_mark_suspicious(dns_stats_t *d, const pkt_t *p, const char *name)
{
    d->suspicious++;
    for (size_t i = 0; i < d->nsusp; i++) {
        if (ip_cmp(&d->susp[i].src, &p->src) == 0) {
            d->susp[i].count++;
            d->susp[i].last_ts = p->ts;
            return;
        }
    }
    if (d->nsusp == d->capsusp) {
        d->capsusp = d->capsusp ? d->capsusp * 2 : 16;
        d->susp = xrealloc(d->susp, d->capsusp * sizeof *d->susp);
    }
    dns_susp_t *s = &d->susp[d->nsusp++];
    memset(s, 0, sizeof *s);
    s->src = p->src;
    s->count = 1;
    s->first_ts = s->last_ts = p->ts;
    snprintf(s->example, sizeof s->example, "%s", name);
}

void dns_process(dns_stats_t *d, const pkt_t *p)
{
    const uint8_t *m = p->payload;
    uint32_t n = p->payload_cap;
    if (!m || n < 12) {
        d->malformed++;
        return;
    }
    uint16_t flags = rd16(m + 2);
    uint16_t qdcount = rd16(m + 4);
    int is_response = flags >> 15;
    int rcode = flags & 0x0F;

    if (is_response) {
        d->responses++;
        if (rcode == 3)
            d->nxdomain++;
        else if (rcode == 2)
            d->servfail++;
        return;          /* charakterystykę nazw liczymy dla zapytań */
    }
    d->queries++;
    if (qdcount == 0)
        return;

    /* Nazwa z pierwszego pytania (sekwencja etykiet zakończona zerem). */
    char name[256];
    size_t nl = 0, lstart = 0, llen = 0;
    uint32_t off = 12;
    int ok = 0;
    unsigned maxlabel = 0;
    for (int guard = 0; guard < 128; guard++) {
        if (off >= n)
            break;
        uint8_t l = m[off];
        if (l == 0) {
            off++;
            ok = 1;
            break;
        }
        if (l & 0xC0)    /* kompresja w sekcji pytań - nieobsługiwana */
            break;
        if (off + 1 + l > n)
            break;
        if (nl && nl < sizeof name - 1)
            name[nl++] = '.';
        size_t start = nl;
        for (unsigned i = 0; i < l && nl < sizeof name - 1; i++) {
            uint8_t c = m[off + 1 + i];
            name[nl++] = (c >= 33 && c < 127) ? (char)c : '?';
        }
        if (l > maxlabel) {
            maxlabel = l;
            lstart = start;
            llen = nl - start;
        }
        off += 1u + l;
    }
    name[nl] = '\0';
    if (!ok) {
        d->malformed++;
        return;
    }

    uint16_t qtype = (off + 2 <= n) ? rd16(m + off) : 0;
    switch (qtype) {
    case 1:   d->qt_a++; break;
    case 28:  d->qt_aaaa++; break;
    case 16:  d->qt_txt++; break;
    case 15:  d->qt_mx++; break;
    case 255: d->qt_any++; break;
    default:  d->qt_other++; break;
    }

    d->qname_sum += (double)nl;
    if (nl > d->max_qname) {
        d->max_qname = (uint32_t)nl;
        snprintf(d->longest, sizeof d->longest, "%s", name);
    }

    /* Heurystyka tunelowania: bardzo długie etykiety lub długie etykiety
     * o wysokiej entropii (dane zakodowane base32/base64/hex). */
    double ent = shannon_entropy(name + lstart, llen);
    int susp = maxlabel >= 40 || nl >= 90 || (maxlabel >= 24 && ent >= 3.8);
    if (susp)
        dns_mark_suspicious(d, p, name);
}
