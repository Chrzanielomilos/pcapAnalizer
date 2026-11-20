/*
 * flow.c - tablica przepływów (haszowanie z łańcuchowaniem, automatyczne
 * powiększanie) oraz maszyna stanów i analiza numerów sekwencyjnych TCP.
 */
#include "flow.h"

#include <stdlib.h>
#include <string.h>

#define INITIAL_BUCKETS 4096

#define SEQ_GT(a, b) ((int32_t)((uint32_t)(a) - (uint32_t)(b)) > 0)

void flow_table_init(flow_table_t *t)
{
    memset(t, 0, sizeof *t);
    t->nbuckets = INITIAL_BUCKETS;
    t->buckets = xcalloc(t->nbuckets, sizeof *t->buckets);
}

void flow_table_free(flow_table_t *t)
{
    for (size_t i = 0; i < t->n; i++)
        free(t->list[i]);
    free(t->list);
    free(t->buckets);
    memset(t, 0, sizeof *t);
}

static uint32_t key_hash(const flow_key_t *k)
{
    return fnv1a(k, sizeof *k);
}

static void rehash(flow_table_t *t)
{
    size_t nb = t->nbuckets * 2;
    flow_t **b = xcalloc(nb, sizeof *b);
    for (size_t i = 0; i < t->nbuckets; i++) {
        flow_t *f = t->buckets[i];
        while (f) {
            flow_t *next = f->hnext;
            size_t h = key_hash(&f->key) & (nb - 1);
            f->hnext = b[h];
            b[h] = f;
            f = next;
        }
    }
    free(t->buckets);
    t->buckets = b;
    t->nbuckets = nb;
}

static int endpoint_cmp(const ip_addr_t *x, uint16_t px,
                        const ip_addr_t *y, uint16_t py)
{
    int c = ip_cmp(x, y);
    if (c)
        return c;
    return (px > py) - (px < py);
}

static int is_server_port(uint8_t proto, uint16_t port)
{
    return port < 1024 || service_name(proto, port) != NULL;
}

/* Czy nadawca pierwszego zaobserwowanego pakietu jest inicjatorem? */
static int src_is_initiator(const pkt_t *p)
{
    if (p->proto == IPP_TCP) {
        uint8_t f = p->tcp_flags;
        if ((f & TCP_SYN) && !(f & TCP_ACK))
            return 1;
        if ((f & TCP_SYN) && (f & TCP_ACK))
            return 0;
    }
    /* Brak SYN (lub UDP): stroną serwerową jest port dobrze znany. */
    if (is_server_port(p->proto, p->sport) && !is_server_port(p->proto, p->dport))
        return 0;
    return 1;
}

flow_t *flow_table_get(flow_table_t *t, const pkt_t *p, double idle_timeout,
                       int *dir, int *created)
{
    flow_key_t k;
    int src_side;

    memset(&k, 0, sizeof k);
    if (endpoint_cmp(&p->src, p->sport, &p->dst, p->dport) <= 0) {
        k.a = p->src; k.pa = p->sport;
        k.b = p->dst; k.pb = p->dport;
        src_side = 0;
    } else {
        k.a = p->dst; k.pa = p->dport;
        k.b = p->src; k.pb = p->sport;
        src_side = 1;
    }
    k.proto = p->proto;

    uint32_t h = key_hash(&k);
    flow_t **link = &t->buckets[h & (t->nbuckets - 1)];
    while (*link && memcmp(&(*link)->key, &k, sizeof k) != 0)
        link = &(*link)->hnext;
    flow_t *f = *link;

    *created = 0;
    if (f) {
        /* Nowe połączenie na tej samej piątce: po czasie bezczynności
         * lub nowy SYN po zakończeniu (FIN/RST) poprzedniego połączenia. */
        int expire = (p->ts - f->last_ts) > idle_timeout;
        if (p->proto == IPP_TCP &&
            (p->tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN &&
            (f->saw_rst || f->fin_mask == 3))
            expire = 1;
        if (expire) {
            *link = f->hnext;       /* stary przepływ pozostaje na liście */
            t->active--;
            f = NULL;
        }
    }

    if (!f) {
        f = xcalloc(1, sizeof *f);
        f->key = k;
        f->id = (uint32_t)t->n + 1;
        f->init = (uint8_t)(src_is_initiator(p) ? src_side : 1 - src_side);
        f->first_ts = f->last_ts = p->ts;
        f->rtt = -1.0;
        f->wscale[0] = f->wscale[1] = -1;
        if (p->proto == IPP_TCP && !(p->tcp_flags & TCP_SYN))
            f->midstream = 1;

        if (t->active + 1 > t->nbuckets)
            rehash(t);
        size_t idx = h & (t->nbuckets - 1);
        f->hnext = t->buckets[idx];
        t->buckets[idx] = f;
        t->active++;

        if (t->n == t->cap) {
            t->cap = t->cap ? t->cap * 2 : 1024;
            t->list = xrealloc(t->list, t->cap * sizeof *t->list);
        }
        t->list[t->n++] = f;
        *created = 1;
    }

    *dir = (src_side == f->init) ? 0 : 1;
    return f;
}

unsigned flow_update(flow_t *f, const pkt_t *p, int dir)
{
    unsigned ev = 0;
    int o = 1 - dir;

    if (p->ts > f->last_ts)
        f->last_ts = p->ts;
    if (p->ts < f->first_ts)
        f->first_ts = p->ts;
    f->pkts[dir]++;
    f->bytes[dir] += p->wirelen;
    f->payload[dir] += p->l4_payload_len;

    if (p->proto != IPP_TCP)
        return 0;

    uint8_t fl = p->tcp_flags;
    int syn = fl & TCP_SYN, ack = fl & TCP_ACK;
    int fin = fl & TCP_FIN, rst = fl & TCP_RST;
    f->flags_or[dir] |= fl;

    /* --- uzgadnianie trójetapowe --- */
    if (syn && !ack) {
        if (f->saw_syn) {
            f->syn_retx++;
        } else {
            f->saw_syn = 1;
            f->syn_ts = p->ts;
        }
        if (p->mss)
            f->mss[dir] = p->mss;
        f->wscale[dir] = (int8_t)p->wscale;
    } else if (syn && ack) {
        if (!f->saw_synack) {
            f->saw_synack = 1;
            f->synack_ts = p->ts;
        }
        if (p->mss)
            f->mss[dir] = p->mss;
        f->wscale[dir] = (int8_t)p->wscale;
    } else if (ack && !rst && f->saw_synack && !f->saw_hs_ack && dir == 0) {
        f->saw_hs_ack = 1;
        f->hs_ts = p->ts;
        if (f->saw_syn && p->ts >= f->syn_ts)
            f->rtt = p->ts - f->syn_ts;
    }
    if (fin)
        f->fin_mask |= (uint8_t)(1u << dir);
    if (rst) {
        if (!f->saw_rst)
            f->rst_dir = (uint8_t)dir;
        f->saw_rst = 1;
    }

    /* --- zerowe okno odbiorcze --- */
    if (p->win == 0 && !syn && !rst && !fin) {
        f->zerowin[dir]++;
        ev |= EV_ZEROWIN;
    }
    if (rst)
        return ev;

    /* --- analiza numerów sekwencyjnych --- */
    uint32_t seglen = p->l4_payload_len + (syn ? 1u : 0u) + (fin ? 1u : 0u);
    if (!f->seq_valid[dir]) {
        f->seq_valid[dir] = 1;
        f->next_seq[dir] = p->seq + seglen;
        if (p->l4_payload_len)
            f->data_segs[dir]++;
    } else if (seglen > 0) {
        uint32_t end = p->seq + seglen;
        if (p->seq == f->next_seq[dir]) {
            f->next_seq[dir] = end;                 /* segment w kolejności */
        } else if (SEQ_GT(p->seq, f->next_seq[dir])) {
            f->gaps[dir]++;                         /* luka: brak segmentu   */
            f->gap_ts[dir] = p->ts;
            f->next_seq[dir] = end;
            ev |= EV_GAP;
        } else {
            /* segment z numerem niższym od oczekiwanego */
            if (p->l4_payload_len <= 1 && !syn && !fin &&
                p->seq + 1 == f->next_seq[dir]) {
                f->keepalive[dir]++;
            } else {
                double window = f->rtt > 0 ? PA_MAX(f->rtt * 0.5, 0.001) : 0.003;
                if (f->gaps[dir] > 0 && p->ts - f->gap_ts[dir] < window) {
                    f->ooo[dir]++;                  /* wypełnienie luki      */
                    f->gaps[dir]--;
                    ev |= EV_OOO;
                } else {
                    f->retrans[dir]++;
                    ev |= EV_RETRANS;
                }
            }
            if (SEQ_GT(end, f->next_seq[dir]))
                f->next_seq[dir] = end;
        }
        if (p->l4_payload_len)
            f->data_segs[dir]++;
    }

    /* --- zduplikowane potwierdzenia --- */
    if (ack && !syn && !fin && p->l4_payload_len == 0) {
        if (f->ack_valid[dir] && p->ack == f->last_ack[dir] &&
            p->win == f->last_win[dir] && f->seq_valid[o] &&
            SEQ_GT(f->next_seq[o], p->ack)) {
            f->dupack[dir]++;
            ev |= EV_DUPACK;
        }
    }
    if (ack) {
        f->last_ack[dir] = p->ack;
        f->last_win[dir] = p->win;
        f->ack_valid[dir] = 1;
    }
    return ev;
}

flow_class_t flow_classify(const flow_t *f)
{
    if (f->key.proto != IPP_TCP)
        return (f->pkts[0] && f->pkts[1]) ? FC_UDP_BIDIR : FC_UDP_UNIDIR;
    if (f->midstream)
        return FC_MIDSTREAM;
    if (!f->saw_synack) {
        if (f->pkts[1] > 0 && (f->flags_or[1] & TCP_RST))
            return FC_REJECTED;
        return FC_UNANSWERED;
    }
    if (!f->saw_hs_ack)
        return FC_HALF_OPEN;
    if (f->saw_rst)
        return FC_RESET;
    if (f->fin_mask == 3)
        return FC_COMPLETE;
    return FC_OPEN;
}

const char *flow_class_name(flow_class_t c)
{
    static const char *const names[FC_COUNT] = {
        "TCP zakończone (FIN)",
        "TCP zerwane (RST)",
        "TCP otwarte/aktywne",
        "TCP półotwarte (brak ACK)",
        "TCP odrzucone (RST na SYN)",
        "TCP bez odpowiedzi na SYN",
        "TCP rozpoczęte przed zapisem",
        "UDP dwukierunkowe",
        "UDP jednokierunkowe",
    };
    return ((unsigned)c < FC_COUNT) ? names[c] : "?";
}
