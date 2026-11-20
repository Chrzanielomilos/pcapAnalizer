/*
 * pcapgen.c - generator syntetycznych plików pcap do testowania pcapanalyzer.
 *
 * Tworzy sześć scenariuszy (ruch prawidłowy, skanowanie portów, SYN flood,
 * UDP flood z tunelowaniem DNS, problemy jakości TCP, Linux SLL + IPv6).
 * Generator jest w pełni deterministyczny (własny PRNG xorshift32 z ustalonym
 * ziarnem dla każdego scenariusza), więc kolejne uruchomienia dają identyczne
 * pliki. Wymaga jedynie standardowej biblioteki C.
 *
 * Użycie: pcapgen [katalog]   (domyślnie tests/pcap)
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BASE_TS 1795078800.0   /* 2026-11-19 09:00:00 UTC */

#define F_FIN 0x01
#define F_SYN 0x02
#define F_RST 0x04
#define F_PSH 0x08
#define F_ACK 0x10
#define F_URG 0x20

#define CWIN 64240
#define SWIN 65160

/* ======================= bufor pakietów ======================= */

typedef struct {
    double   ts;
    uint32_t idx;
    uint32_t len;
    uint8_t *data;
} gpkt_t;

static gpkt_t  *P;
static size_t   NP, CAPP;
static uint32_t RNG = 1;
static int      LINKTYPE = 1;      /* 1 = Ethernet, 113 = Linux SLL */
static uint16_t IPID = 1;

static uint32_t rnd(void)
{
    uint32_t x = RNG;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    RNG = x;
    return x;
}

static double rndf(void)
{
    return (double)(rnd() >> 8) / 16777216.0;
}

static int rndint(int lo, int hi)
{
    return lo + (int)(rnd() % (uint32_t)(hi - lo + 1));
}

static void add_pkt(double ts, const uint8_t *d, int len)
{
    if (NP == CAPP) {
        CAPP = CAPP ? CAPP * 2 : 4096;
        P = realloc(P, CAPP * sizeof *P);
        if (!P) {
            fprintf(stderr, "brak pamięci\n");
            exit(1);
        }
    }
    P[NP].ts = ts;
    P[NP].idx = (uint32_t)NP;
    P[NP].len = (uint32_t)len;
    P[NP].data = malloc((size_t)len);
    if (!P[NP].data) {
        fprintf(stderr, "brak pamięci\n");
        exit(1);
    }
    memcpy(P[NP].data, d, (size_t)len);
    NP++;
}

static int cmp_pkt(const void *a, const void *b)
{
    const gpkt_t *x = a, *y = b;
    if (x->ts < y->ts) return -1;
    if (x->ts > y->ts) return 1;
    return (x->idx > y->idx) - (x->idx < y->idx);
}

static void wr16(FILE *f, uint32_t v)
{
    uint8_t b[2] = {(uint8_t)v, (uint8_t)(v >> 8)};
    fwrite(b, 1, 2, f);
}

static void wr32(FILE *f, uint32_t v)
{
    uint8_t b[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
    fwrite(b, 1, 4, f);
}

static void write_pcap(const char *dir, const char *name)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    qsort(P, NP, sizeof *P, cmp_pkt);
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror(path);
        exit(1);
    }
    wr32(f, 0xa1b2c3d4u);
    wr16(f, 2);
    wr16(f, 4);
    wr32(f, 0);
    wr32(f, 0);
    wr32(f, 65535);
    wr32(f, (uint32_t)LINKTYPE);
    for (size_t i = 0; i < NP; i++) {
        uint32_t sec = (uint32_t)P[i].ts;
        uint32_t usec = (uint32_t)((P[i].ts - (double)sec) * 1000000.0 + 0.5);
        if (usec >= 1000000) {
            sec++;
            usec -= 1000000;
        }
        wr32(f, sec);
        wr32(f, usec);
        wr32(f, P[i].len);
        wr32(f, P[i].len);
        fwrite(P[i].data, 1, P[i].len, f);
        free(P[i].data);
    }
    fclose(f);
    printf("%s: %zu pakietów\n", path, NP);
    NP = 0;
}

/* ======================= budowa ramek ======================= */

typedef struct {
    int     v6;
    int     local;
    uint8_t ip[16];
    uint8_t mac[6];
    uint8_t ttl;
} ghost_t;

static ghost_t h4(int a, int b, int c, int d)
{
    ghost_t h;
    memset(&h, 0, sizeof h);
    h.ip[0] = (uint8_t)a;
    h.ip[1] = (uint8_t)b;
    h.ip[2] = (uint8_t)c;
    h.ip[3] = (uint8_t)d;
    h.local = (a == 192 && b == 168);
    h.mac[0] = 0x02;
    if (h.local) {
        h.mac[3] = (uint8_t)c;
        h.mac[4] = (uint8_t)d;
        h.mac[5] = 0x01;
        h.ttl = 64;
    } else {
        h.mac[5] = 0xfe;        /* adres MAC bramy */
        h.ttl = 52;
    }
    return h;
}

static ghost_t h6(int g0, int g1, int g2, int g7, int local)
{
    ghost_t h;
    memset(&h, 0, sizeof h);
    h.v6 = 1;
    h.local = local;
    h.ip[0] = (uint8_t)(g0 >> 8); h.ip[1] = (uint8_t)g0;
    h.ip[2] = (uint8_t)(g1 >> 8); h.ip[3] = (uint8_t)g1;
    h.ip[4] = (uint8_t)(g2 >> 8); h.ip[5] = (uint8_t)g2;
    h.ip[14] = (uint8_t)(g7 >> 8); h.ip[15] = (uint8_t)g7;
    h.mac[0] = 0x02;
    if (local) {
        h.mac[4] = (uint8_t)g7;
        h.mac[5] = 0x06;
        h.ttl = 64;
    } else {
        h.mac[5] = 0xfe;
        h.ttl = 55;
    }
    return h;
}

static uint8_t FB[2048], L4[2048], PL[2048];

static void put16(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t csum_add(uint32_t s, const uint8_t *d, int n)
{
    int i;
    for (i = 0; i + 1 < n; i += 2)
        s += ((uint32_t)d[i] << 8) | d[i + 1];
    if (n & 1)
        s += (uint32_t)d[n - 1] << 8;
    return s;
}

static uint16_t csum_fold(uint32_t s)
{
    while (s >> 16)
        s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t)(~s & 0xFFFF);
}

static int l2_header(uint8_t *f, const ghost_t *s, const ghost_t *d, uint32_t etype, int vlan)
{
    int off;
    if (LINKTYPE == 1) {
        memcpy(f, d->mac, 6);
        memcpy(f + 6, s->mac, 6);
        off = 12;
        if (vlan) {
            put16(f + off, 0x8100);
            put16(f + off + 2, (uint32_t)vlan);
            off += 4;
        }
        put16(f + off, etype);
        off += 2;
    } else {                           /* Linux cooked capture (SLL) */
        put16(f, s->local ? 4 : 0);    /* 4 = wychodzący, 0 = do hosta */
        put16(f + 2, 1);
        put16(f + 4, 6);
        memcpy(f + 6, s->mac, 6);
        f[12] = 0;
        f[13] = 0;
        put16(f + 14, etype);
        off = 16;
    }
    return off;
}

static void emit_ip(double ts, const ghost_t *s, const ghost_t *d, int proto,
                    uint8_t *l4, int l4len, int vlan)
{
    uint8_t *f = FB;
    int off = l2_header(f, s, d, s->v6 ? 0x86DD : 0x0800, vlan);
    int co = proto == 6 ? 16 : proto == 17 ? 6 : proto == 1 ? 2 : -1;
    if (co >= 0) {
        uint32_t sum = 0;
        uint16_t c;
        l4[co] = 0;
        l4[co + 1] = 0;
        if (proto != 1) {              /* pseudo-nagłówek */
            sum = csum_add(sum, s->ip, s->v6 ? 16 : 4);
            sum = csum_add(sum, d->ip, s->v6 ? 16 : 4);
            sum += (uint32_t)proto;
            sum += (uint32_t)l4len;
        }
        sum = csum_add(sum, l4, l4len);
        c = csum_fold(sum);
        if (proto == 17 && c == 0)
            c = 0xFFFF;
        put16(l4 + co, c);
    }
    uint8_t *ip = f + off;
    if (!s->v6) {
        ip[0] = 0x45;
        ip[1] = 0;
        put16(ip + 2, (uint32_t)(20 + l4len));
        put16(ip + 4, IPID);
        IPID++;
        put16(ip + 6, 0x4000);
        ip[8] = s->ttl;
        ip[9] = (uint8_t)proto;
        ip[10] = 0;
        ip[11] = 0;
        memcpy(ip + 12, s->ip, 4);
        memcpy(ip + 16, d->ip, 4);
        put16(ip + 10, csum_fold(csum_add(0, ip, 20)));
        off += 20;
    } else {
        ip[0] = 0x60;
        ip[1] = 0;
        ip[2] = 0;
        ip[3] = 0;
        put16(ip + 4, (uint32_t)l4len);
        ip[6] = (uint8_t)proto;
        ip[7] = s->ttl;
        memcpy(ip + 8, s->ip, 16);
        memcpy(ip + 24, d->ip, 16);
        off += 40;
    }
    memcpy(f + off, l4, (size_t)l4len);
    off += l4len;
    add_pkt(ts, f, off);
}

static void emit_arp(double ts, const ghost_t *s, const ghost_t *target)
{
    uint8_t *f = FB;
    ghost_t bc = *s;
    memset(bc.mac, 0xFF, 6);
    int off = l2_header(f, s, &bc, 0x0806, 0);
    uint8_t *a = f + off;
    put16(a, 1);
    put16(a + 2, 0x0800);
    a[4] = 6;
    a[5] = 4;
    put16(a + 6, 1);
    memcpy(a + 8, s->mac, 6);
    memcpy(a + 14, s->ip, 4);
    memset(a + 18, 0, 6);
    memcpy(a + 24, target->ip, 4);
    add_pkt(ts, f, off + 28);
}

static void tcp_seg(double ts, const ghost_t *s, const ghost_t *d, int sp, int dp,
                    uint32_t seq, uint32_t ack, int flags, int win, int plen, int vlan)
{
    static const uint8_t opt[12] = {2, 4, 0x05, 0xB4, 1, 1, 4, 2, 1, 3, 3, 7};
    uint8_t *t = L4;
    int hl = 20, i;
    memset(t, 0, 64);
    put16(t, (uint32_t)sp);
    put16(t + 2, (uint32_t)dp);
    put32(t + 4, seq);
    put32(t + 8, (flags & F_ACK) ? ack : 0);
    if ((flags & F_SYN) && !(flags & F_RST)) {   /* MSS, SACK, WS */
        memcpy(t + 20, opt, 12);
        hl = 32;
    }
    t[12] = (uint8_t)((hl / 4) << 4);
    t[13] = (uint8_t)flags;
    put16(t + 14, (uint32_t)win);
    for (i = 0; i < plen; i++)
        t[hl + i] = (uint8_t)('a' + (i % 26));
    emit_ip(ts, s, d, 6, t, hl + plen, vlan);
}

static void udp_pkt(double ts, const ghost_t *s, const ghost_t *d, int sp, int dp,
                    const uint8_t *pl, int plen, int vlan)
{
    uint8_t *u = L4;
    put16(u, (uint32_t)sp);
    put16(u + 2, (uint32_t)dp);
    put16(u + 4, (uint32_t)(8 + plen));
    put16(u + 6, 0);
    memcpy(u + 8, pl, (size_t)plen);
    emit_ip(ts, s, d, 17, u, 8 + plen, vlan);
}

static void icmp_echo(double ts, const ghost_t *s, const ghost_t *d, int id, int seq, int reply)
{
    uint8_t *c = L4;
    int i;
    c[0] = (uint8_t)(reply ? 0 : 8);
    c[1] = 0;
    c[2] = 0;
    c[3] = 0;
    put16(c + 4, (uint32_t)id);
    put16(c + 6, (uint32_t)seq);
    for (i = 0; i < 32; i++)
        c[8 + i] = (uint8_t)('A' + (i % 26));
    emit_ip(ts, s, d, 1, c, 40, 0);
}

/* ======================= DNS ======================= */

static int dns_msg(uint8_t *b, int id, int resp, const char *name, int qtype, int rcode)
{
    int off = 12, i, an = (resp && rcode == 0) ? 1 : 0;
    const char *p = name;
    put16(b, (uint32_t)id);
    put16(b + 2, resp ? (uint32_t)(0x8180 | rcode) : 0x0100);
    put16(b + 4, 1);
    put16(b + 6, (uint32_t)an);
    put16(b + 8, 0);
    put16(b + 10, 0);
    while (*p) {
        const char *dot = strchr(p, '.');
        int l = dot ? (int)(dot - p) : (int)strlen(p);
        b[off++] = (uint8_t)l;
        memcpy(b + off, p, (size_t)l);
        off += l;
        p += l;
        if (*p == '.')
            p++;
    }
    b[off++] = 0;
    put16(b + off, (uint32_t)qtype);
    put16(b + off + 2, 1);
    off += 4;
    if (an) {
        put16(b + off, 0xC00C);
        put16(b + off + 2, (uint32_t)qtype);
        put16(b + off + 4, 1);
        put32(b + off + 6, 300);
        off += 10;
        if (qtype == 1) {
            put16(b + off, 4);
            b[off + 2] = 93; b[off + 3] = 184; b[off + 4] = 216; b[off + 5] = 34;
            off += 6;
        } else if (qtype == 28) {
            put16(b + off, 16);
            memset(b + off + 2, 0, 16);
            b[off + 2] = 0x20; b[off + 3] = 0x01; b[off + 4] = 0x0D; b[off + 5] = 0xB8;
            b[off + 17] = 1;
            off += 18;
        } else if (qtype == 16) {
            put16(b + off, 61);
            b[off + 2] = 60;
            for (i = 0; i < 60; i++)
                b[off + 3 + i] = (uint8_t)('a' + (i * 7) % 26);
            off += 63;
        } else {
            put16(b + off, 0);
            off += 2;
        }
    }
    return off;
}

static void dns_exchange(double t, const ghost_t *cli, const ghost_t *srv, const char *name,
                         int qtype, int rcode)
{
    int sp = rndint(20000, 60999);
    int id = (int)(rnd() & 0xFFFF);
    double delay = 0.004 + rndf() * 0.02;
    int n = dns_msg(PL, id, 0, name, qtype, 0);
    udp_pkt(t, cli, srv, sp, 53, PL, n, 0);
    n = dns_msg(PL, id, 1, name, qtype, rcode);
    udp_pkt(t + delay, srv, cli, 53, sp, PL, n, 0);
}

/* ======================= sesje TCP ======================= */

/* Punkt przechwytywania przy kliencie: segmenty klienta w chwili t,
 * odpowiedzi serwera po czasie RTT. */
typedef struct {
    const ghost_t *c, *s;
    int      cp, sp;
    uint32_t cs, ss;
    double   rtt;
    int      vlan;
} conn_t;

static void conn_init(conn_t *k, const ghost_t *c, const ghost_t *s, int sp, double rtt, int vlan)
{
    k->c = c;
    k->s = s;
    k->sp = sp;
    k->rtt = rtt;
    k->vlan = vlan;
    k->cp = rndint(32768, 60999);
    k->cs = rnd();
    k->ss = rnd();
}

static double conn_open(conn_t *k, double t)
{
    tcp_seg(t, k->c, k->s, k->cp, k->sp, k->cs, 0, F_SYN, CWIN, 0, k->vlan);
    k->cs++;
    t += k->rtt;
    tcp_seg(t, k->s, k->c, k->sp, k->cp, k->ss, k->cs, F_SYN | F_ACK, SWIN, 0, k->vlan);
    k->ss++;
    t += 0.0001;
    tcp_seg(t, k->c, k->s, k->cp, k->sp, k->cs, k->ss, F_ACK, CWIN, 0, k->vlan);
    return t;
}

static double conn_xfer(conn_t *k, double t, int req, int resp)
{
    int sent = 0, segs = 0;
    t += 0.0005;
    while (sent < req) {
        int n = req - sent;
        if (n > 1448)
            n = 1448;
        tcp_seg(t, k->c, k->s, k->cp, k->sp, k->cs, k->ss, F_ACK | F_PSH, CWIN, n, k->vlan);
        k->cs += (uint32_t)n;
        sent += n;
        t += 0.00005;
    }
    t += k->rtt;
    sent = 0;
    while (sent < resp) {
        int n = resp - sent;
        if (n > 1448)
            n = 1448;
        sent += n;
        segs++;
        tcp_seg(t, k->s, k->c, k->sp, k->cp, k->ss, k->cs,
                F_ACK | (sent >= resp ? F_PSH : 0), SWIN, n, k->vlan);
        k->ss += (uint32_t)n;
        if (segs % 2 == 0 || sent >= resp)
            tcp_seg(t + 0.00004, k->c, k->s, k->cp, k->sp, k->cs, k->ss, F_ACK, CWIN, 0, k->vlan);
        t += 0.00012;
    }
    return t;
}

static double conn_close(conn_t *k, double t)
{
    t += 0.001;
    tcp_seg(t, k->c, k->s, k->cp, k->sp, k->cs, k->ss, F_FIN | F_ACK, CWIN, 0, k->vlan);
    k->cs++;
    t += k->rtt;
    tcp_seg(t, k->s, k->c, k->sp, k->cp, k->ss, k->cs, F_FIN | F_ACK, SWIN, 0, k->vlan);
    k->ss++;
    t += 0.0001;
    tcp_seg(t, k->c, k->s, k->cp, k->sp, k->cs, k->ss, F_ACK, CWIN, 0, k->vlan);
    return t;
}

/* ======================= hosty i ruch tła ======================= */

static ghost_t LAN[50];          /* 192.168.1.10 - 192.168.1.59 */
static ghost_t GW;               /* 192.168.1.1 - brama i resolver DNS */
static ghost_t WEB[8];
static ghost_t NTP_SRV, SSH_SRV;
static ghost_t V6C[4], V6S[2];

static const char *const WEB_NAMES[8] = {
    "www.example.com", "cdn.example.net", "api.github.com", "www.wikipedia.org",
    "fonts.gstatic.com", "archive.ubuntu.com", "mail.example.org", "static.cloudflare.net"
};

static void init_hosts(void)
{
    int i;
    for (i = 0; i < 50; i++)
        LAN[i] = h4(192, 168, 1, 10 + i);
    GW = h4(192, 168, 1, 1);
    WEB[0] = h4(93, 184, 216, 34);
    WEB[1] = h4(151, 101, 1, 69);
    WEB[2] = h4(140, 82, 121, 4);
    WEB[3] = h4(185, 15, 59, 224);
    WEB[4] = h4(142, 250, 74, 46);
    WEB[5] = h4(91, 189, 91, 38);
    WEB[6] = h4(17, 253, 144, 10);
    WEB[7] = h4(104, 16, 132, 229);
    NTP_SRV = h4(162, 159, 200, 1);
    SSH_SRV = h4(10, 0, 0, 5);
    for (i = 0; i < 4; i++)
        V6C[i] = h6(0x2001, 0x0db8, 0x0001, 0x10 + i, 1);
    V6S[0] = h6(0x2001, 0x0db8, 0x00ff, 0x0443, 0);
    V6S[1] = h6(0x2001, 0x0db8, 0x00ff, 0x0080, 0);
}

static void bg_web(double t0, double dur, int nsess, int nclients)
{
    int i, j;
    for (i = 0; i < nsess; i++) {
        double t = t0 + rndf() * dur;
        int ci = rndint(0, nclients - 1);
        int si = rndint(0, 7);
        int https = (rnd() % 10) < 8;
        double rtt = 0.010 + rndf() * 0.070;
        int req = rndint(200, 900);
        int resp = rndint(1000, 30000);
        int nreq = rndint(1, 3);
        conn_t k;
        dns_exchange(t, &LAN[ci], &GW, WEB_NAMES[si], 1, 0);
        t += 0.03;
        conn_init(&k, &LAN[ci], &WEB[si], https ? 443 : 80, rtt, 0);
        t = conn_open(&k, t);
        for (j = 0; j < nreq; j++) {
            t = conn_xfer(&k, t, req, resp / (j + 1));
            t += 0.05 + rndf() * 0.3;
        }
        conn_close(&k, t);
    }
}

static void bg_v6(double t0, double dur, int nsess)
{
    int i;
    for (i = 0; i < nsess; i++) {
        double t = t0 + rndf() * dur;
        int ci = rndint(0, 3);
        int si = rndint(0, 1);
        double rtt = 0.015 + rndf() * 0.05;
        int resp = rndint(2000, 25000);
        conn_t k;
        dns_exchange(t, &LAN[ci], &GW, "ipv6.example.net", 28, 0);
        t += 0.03;
        conn_init(&k, &V6C[ci], &V6S[si], si == 0 ? 443 : 80, rtt, 0);
        t = conn_open(&k, t);
        t = conn_xfer(&k, t, 400, resp);
        conn_close(&k, t);
    }
}

static void bg_ntp(double t0, double dur, const ghost_t *cli, double period)
{
    uint8_t q[48], r[48];
    double t;
    memset(q, 0, 48);
    memset(r, 0, 48);
    q[0] = 0x23;
    r[0] = 0x24;
    r[1] = 2;
    for (t = t0 + 2.0; t < t0 + dur; t += period) {
        udp_pkt(t, cli, &NTP_SRV, 123, 123, q, 48, 0);
        udp_pkt(t + 0.018, &NTP_SRV, cli, 123, 123, r, 48, 0);
    }
}

static void bg_ssh(double t0, double dur, const ghost_t *cli, const ghost_t *srv, int vlan)
{
    conn_t k;
    double t = t0 + 0.5;
    conn_init(&k, cli, srv, 22, 0.002, vlan);
    t = conn_open(&k, t);
    while (t < t0 + dur - 1.0) {
        int n = rndint(36, 120);
        int m;
        tcp_seg(t, k.c, k.s, k.cp, k.sp, k.cs, k.ss, F_PSH | F_ACK, CWIN, n, vlan);
        k.cs += (uint32_t)n;
        m = rndint(36, 200);
        tcp_seg(t + k.rtt, k.s, k.c, k.sp, k.cp, k.ss, k.cs, F_PSH | F_ACK, SWIN, m, vlan);
        k.ss += (uint32_t)m;
        tcp_seg(t + k.rtt + 0.00005, k.c, k.s, k.cp, k.sp, k.cs, k.ss, F_ACK, CWIN, 0, vlan);
        t += 0.3 + rndf() * 1.5;
    }
}

static void pings(double t0, double dur, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        double t = t0 + rndf() * dur;
        int ci = rndint(0, 9);
        icmp_echo(t, &LAN[ci], &WEB[0], 0x1234, i + 1, 0);
        icmp_echo(t + 0.021, &WEB[0], &LAN[ci], 0x1234, i + 1, 1);
    }
}

static void arps(double t0, double dur, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        double t = t0 + rndf() * dur;
        int ci = rndint(0, 19);
        emit_arp(t, &LAN[ci], &GW);
    }
}

/* ======================= scenariusze ======================= */

static void scen_normal(const char *dir)
{
    double t0 = BASE_TS;
    RNG = 1001;
    LINKTYPE = 1;
    bg_web(t0, 60.0, 60, 20);
    bg_v6(t0, 60.0, 6);
    bg_ntp(t0, 60.0, &LAN[0], 16.0);
    bg_ssh(t0, 60.0, &LAN[5], &SSH_SRV, 100);
    pings(t0, 60.0, 5);
    arps(t0, 60.0, 6);
    write_pcap(dir, "01_normal_traffic.pcap");
}

static int is_open_port(int port)
{
    return port == 22 || port == 80 || port == 139 || port == 443 || port == 445;
}

static void scen_port_scan(const char *dir)
{
    double t0 = BASE_TS, t;
    ghost_t att = h4(10, 10, 10, 66);
    const ghost_t *tg = &LAN[10];                     /* 192.168.1.20 */
    int port, h, i;
    RNG = 2002;
    LINKTYPE = 1;
    att.ttl = 48;
    bg_web(t0, 30.0, 25, 20);

    /* skanowanie SYN portów 1-1024 hosta 192.168.1.20 */
    t = t0 + 5.0;
    for (port = 1; port <= 1024; port++) {
        uint32_t seq = rnd();
        tcp_seg(t, &att, tg, 54321, port, seq, 0, F_SYN, 1024, 0, 0);
        if (is_open_port(port)) {
            uint32_t isn = rnd();
            tcp_seg(t + 0.0008, tg, &att, port, 54321, isn, seq + 1, F_SYN | F_ACK, SWIN, 0, 0);
            tcp_seg(t + 0.0009, &att, tg, 54321, port, seq + 1, 0, F_RST, 0, 0, 0);
        } else {
            tcp_seg(t + 0.0006, tg, &att, port, 54321, 0, seq + 1, F_RST | F_ACK, 0, 0, 0);
        }
        t += 0.002 + rndf() * 0.001;
    }

    /* skanowanie poziome sieci 192.168.1.0/24 na porcie 445 */
    t = t0 + 12.0;
    for (h = 1; h <= 254; h++) {
        ghost_t dst = h4(192, 168, 1, h);
        uint32_t seq = rnd();
        tcp_seg(t, &att, &dst, 54322, 445, seq, 0, F_SYN, 1024, 0, 0);
        if (h == 20) {
            uint32_t isn = rnd();
            tcp_seg(t + 0.0008, &dst, &att, 445, 54322, isn, seq + 1, F_SYN | F_ACK, SWIN, 0, 0);
            tcp_seg(t + 0.0009, &att, &dst, 54322, 445, seq + 1, 0, F_RST, 0, 0, 0);
        } else if (h % 7 == 0) {
            tcp_seg(t + 0.0007, &dst, &att, 445, 54322, 0, seq + 1, F_RST | F_ACK, 0, 0, 0);
        }
        t += 0.004 + rndf() * 0.002;
    }

    /* skanowanie NULL, XMAS i FIN portów 20-29 */
    t = t0 + 20.0;
    for (i = 0; i < 30; i++) {
        int p = 20 + (i % 10);
        int fl = i < 10 ? 0 : i < 20 ? (F_FIN | F_PSH | F_URG) : F_FIN;
        uint32_t seq = rnd();
        tcp_seg(t, &att, tg, 55000 + i, p, seq, 0, fl, 1024, 0, 0);
        if (p != 22)
            tcp_seg(t + 0.0006, tg, &att, p, 55000 + i, 0, seq, F_RST | F_ACK, 0, 0, 0);
        t += 0.01;
    }
    write_pcap(dir, "02_port_scan.pcap");
}

static void scen_syn_flood(const char *dir)
{
    double t0 = BASE_TS, t;
    ghost_t victim = h4(192, 168, 1, 80);
    int i;
    RNG = 3003;
    LINKTYPE = 1;
    bg_web(t0, 30.0, 30, 20);

    /* prawidłowi klienci serwera WWW */
    for (i = 0; i < 12; i++) {
        conn_t k;
        double ts = t0 + rndf() * 30.0;
        int ci = rndint(0, 19);
        double rtt = 0.0005 + rndf() * 0.001;
        int resp = rndint(2000, 20000);
        conn_init(&k, &LAN[ci], &victim, 80, rtt, 0);
        ts = conn_open(&k, ts);
        ts = conn_xfer(&k, ts, 300, resp);
        conn_close(&k, ts);
    }

    /* atak: 6000 SYN z losowych (sfałszowanych) adresów, 1000 SYN/s */
    t = t0 + 10.0;
    for (i = 0; i < 6000; i++) {
        int a = rndint(1, 223);
        int b = rndint(0, 255);
        int c = rndint(0, 255);
        int d = rndint(1, 254);
        ghost_t src = h4(a, b, c, d);
        int sp = rndint(1024, 65535);
        uint32_t seq = rnd();
        tcp_seg(t, &src, &victim, sp, 80, seq, 0, F_SYN, 512, 0, 0);
        if (i % 3 == 0) {
            uint32_t isn = rnd();
            tcp_seg(t + 0.0003, &victim, &src, 80, sp, isn, seq + 1, F_SYN | F_ACK, SWIN, 0, 0);
        }
        t += 0.001;
    }
    write_pcap(dir, "03_syn_flood.pcap");
}

static void scen_udp_flood_dns_tunnel(const char *dir)
{
    static const char B32[] = "abcdefghijklmnopqrstuvwxyz234567";
    double t0 = BASE_TS, t;
    ghost_t target = h4(192, 168, 1, 100);
    ghost_t fl[5];
    uint8_t junk[512];
    int i, j;
    RNG = 4004;
    LINKTYPE = 1;
    for (i = 0; i < 5; i++)
        fl[i] = h4(203, 0, 113, 50 + i);
    for (i = 0; i < 512; i++)
        junk[i] = (uint8_t)(i * 31 + 7);
    bg_web(t0, 40.0, 30, 20);

    /* UDP flood: 8000 datagramów po 512 B w ciągu 8 s */
    t = t0 + 15.0;
    for (i = 0; i < 8000; i++) {
        int s = rndint(0, 4);
        int sp = rndint(1024, 65535);
        udp_pkt(t, &fl[s], &target, sp, 27015, junk, 512, 0);
        t += 0.001;
    }

    /* tunel DNS: zapytania TXT o nazwy z danymi zakodowanymi w base32 */
    t = t0 + 2.0;
    for (i = 0; i < 60; i++) {
        char lab[64], name[160];
        for (j = 0; j < 52; j++)
            lab[j] = B32[rnd() % 32];
        lab[52] = '\0';
        snprintf(name, sizeof name, "%s.%04d.t.exfil-tunnel.example", lab, i);
        dns_exchange(t, &LAN[23], &GW, name, 16, 0);
        t += 0.4 + rndf() * 0.2;
    }
    write_pcap(dir, "04_udp_flood_dns_tunnel.pcap");
}

/* Pobieranie dużego pliku z utratą segmentów, zamianą kolejności
 * i epizodem zerowego okna (punkt przechwytywania przy kliencie). */
static void bulk_download(double t, const ghost_t *c, const ghost_t *s, int sp, int total,
                          double loss)
{
    conn_t k;
    int sent = 0, win = 0, i;
    conn_init(&k, c, s, sp, 0.040, 0);
    t = conn_open(&k, t);
    t += 0.0005;
    tcp_seg(t, k.c, k.s, k.cp, k.sp, k.cs, k.ss, F_PSH | F_ACK, CWIN, 400, 0);
    k.cs += 400;
    t += k.rtt;
    while (sent < total) {
        uint32_t seg_seq[16], hole = 0, acked;
        int seg_len[16], lost[16], nseg = 0, have_hole = 0;
        double seg_t[16], tend;
        for (i = 0; i < 16 && sent < total; i++) {
            int n = total - sent;
            if (n > 1448)
                n = 1448;
            seg_seq[i] = k.ss;
            seg_len[i] = n;
            seg_t[i] = t + i * 0.00012;
            lost[i] = rndf() < loss;
            k.ss += (uint32_t)n;
            sent += n;
            nseg++;
        }
        for (i = 0; i + 1 < nseg; i++) {
            if (!lost[i] && !lost[i + 1] && rndf() < 0.01) {
                double tmp = seg_t[i];
                seg_t[i] = seg_t[i + 1];
                seg_t[i + 1] = tmp;
                i++;
            }
        }
        acked = seg_seq[0];
        for (i = 0; i < nseg; i++) {
            if (lost[i]) {
                if (!have_hole) {
                    have_hole = 1;
                    hole = seg_seq[i];
                }
                continue;
            }
            tcp_seg(seg_t[i], k.s, k.c, k.sp, k.cp, seg_seq[i], k.cs, F_ACK, SWIN, seg_len[i], 0);
            if (!have_hole) {
                acked = seg_seq[i] + (uint32_t)seg_len[i];
                if (i % 2 == 1 || i == nseg - 1)
                    tcp_seg(seg_t[i] + 0.00004, k.c, k.s, k.cp, k.sp, k.cs, acked, F_ACK, CWIN, 0, 0);
            } else {
                tcp_seg(seg_t[i] + 0.00004, k.c, k.s, k.cp, k.sp, k.cs, hole, F_ACK, CWIN, 0, 0);
            }
        }
        tend = t + nseg * 0.00012;
        if (have_hole) {
            double tr = tend + k.rtt;
            int r = 0;
            for (i = 0; i < nseg; i++) {
                if (lost[i]) {
                    tcp_seg(tr + r * 0.00012, k.s, k.c, k.sp, k.cp, seg_seq[i], k.cs, F_ACK,
                            SWIN, seg_len[i], 0);
                    r++;
                }
            }
            tcp_seg(tr + r * 0.00012 + 0.00004, k.c, k.s, k.cp, k.sp, k.cs, k.ss, F_ACK, CWIN, 0, 0);
            t = tr + r * 0.00012 + k.rtt;
        } else {
            t = tend + k.rtt;
        }
        win++;
        if (win == 30) {
            double tz = t;
            tcp_seg(tz, k.c, k.s, k.cp, k.sp, k.cs, k.ss, F_ACK, 0, 0, 0);
            tcp_seg(tz + 0.2, k.c, k.s, k.cp, k.sp, k.cs, k.ss, F_ACK, 0, 0, 0);
            tcp_seg(tz + 0.5, k.c, k.s, k.cp, k.sp, k.cs, k.ss, F_ACK, CWIN, 0, 0);
            t = tz + 0.5 + k.rtt;
        }
    }
    conn_close(&k, t);
}

static void scen_tcp_problems(const char *dir)
{
    double t0 = BASE_TS;
    ghost_t srv = h4(198, 51, 100, 7);
    ghost_t srv2 = h4(198, 51, 100, 9);
    ghost_t c2 = h4(185, 199, 110, 5);
    int i;
    RNG = 5005;
    LINKTYPE = 1;
    bg_web(t0, 130.0, 20, 20);
    bg_ntp(t0, 130.0, &LAN[0], 16.0);

    bulk_download(t0 + 20.0, &LAN[40], &srv, 80, 1200000, 0.07);   /* 192.168.1.50 */

    /* okresowe połączenia co ~10 s (beaconing) z 192.168.1.57 */
    for (i = 0; i < 13; i++) {
        conn_t k;
        double jitter = (rndf() - 0.5) * 0.4;
        double t = t0 + 5.0 + i * 10.0 + jitter;
        conn_init(&k, &LAN[47], &c2, 8443, 0.035, 0);
        t = conn_open(&k, t);
        t = conn_xfer(&k, t, 300, 1200);
        conn_close(&k, t);
    }

    /* próby połączeń z zamkniętym portem 8080 */
    for (i = 0; i < 5; i++) {
        double t = t0 + 40.0 + i * 3.0;
        int sp = rndint(40000, 50000);
        uint32_t seq = rnd();
        tcp_seg(t, &LAN[41], &srv, sp, 8080, seq, 0, F_SYN, CWIN, 0, 0);
        tcp_seg(t + 0.03, &srv, &LAN[41], 8080, sp, 0, seq + 1, F_RST | F_ACK, 0, 0, 0);
    }

    /* sesje zrywane przez serwer segmentem RST */
    for (i = 0; i < 15; i++) {
        conn_t k;
        double t = t0 + 50.0 + rndf() * 60.0;
        int ci = rndint(0, 19);
        conn_init(&k, &LAN[ci], &srv2, 443, 0.03, 0);
        t = conn_open(&k, t);
        t = conn_xfer(&k, t, 500, 3000);
        tcp_seg(t + 0.01, &srv2, &LAN[ci], 443, k.cp, k.ss, k.cs, F_RST | F_ACK, 0, 0, 0);
    }
    write_pcap(dir, "05_tcp_problems.pcap");
}

static void scen_sll_ipv6(const char *dir)
{
    double t0 = BASE_TS;
    RNG = 6006;
    LINKTYPE = 113;
    bg_v6(t0, 30.0, 15);
    bg_web(t0, 30.0, 10, 20);
    arps(t0, 30.0, 3);
    write_pcap(dir, "06_linux_sll_ipv6.pcap");
    LINKTYPE = 1;
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "tests/pcap";
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        perror(dir);
        return 1;
    }
    init_hosts();
    scen_normal(dir);
    scen_port_scan(dir);
    scen_syn_flood(dir);
    scen_udp_flood_dns_tunnel(dir);
    scen_tcp_problems(dir);
    scen_sll_ipv6(dir);
    free(P);
    return 0;
}
