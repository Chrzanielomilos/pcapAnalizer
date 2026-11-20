/*
 * decoder.c - dekodowanie nagłówków L2-L4.
 *
 * Każdy dostęp do bufora jest poprzedzony kontrolą długości zapisanych
 * danych (caplen), więc uszkodzone lub obcięte ramki nie powodują odczytu
 * poza buforem - są jedynie klasyfikowane jako DEC_TRUNCATED/DEC_MALFORMED.
 */
#include "decoder.h"

#include <pcap/pcap.h>
#include <string.h>

#define ETH_IPV4  0x0800
#define ETH_IPV6  0x86DD
#define ETH_VLAN  0x8100
#define ETH_QINQ  0x88A8
#define ETH_QINQ2 0x9100

static int ipv4_cksum_ok(const uint8_t *h, uint32_t len)
{
    uint32_t s = 0;
    for (uint32_t i = 0; i + 1 < len; i += 2)
        s += rd16(h + i);
    while (s >> 16)
        s = (s & 0xFFFF) + (s >> 16);
    return s == 0xFFFF;
}

static void parse_tcp_options(pkt_t *p, const uint8_t *o, uint32_t len)
{
    uint32_t i = 0;
    while (i < len) {
        uint8_t kind = o[i];
        if (kind == 0)          /* koniec listy opcji */
            break;
        if (kind == 1) {        /* NOP */
            i++;
            continue;
        }
        if (i + 1 >= len)
            break;
        uint8_t olen = o[i + 1];
        if (olen < 2 || i + olen > len)
            break;
        if (kind == 2 && olen == 4)
            p->mss = rd16(o + i + 2);
        else if (kind == 3 && olen == 3)
            p->wscale = o[i + 2];
        else if (kind == 4 && olen == 2)
            p->sack_perm = 1;
        i += olen;
    }
}

/* d     - początek nagłówka L4
 * avail - liczba zapisanych bajtów od początku L4 (ograniczona do l4len)
 * l4len - długość segmentu L4 wynikająca z nagłówka IP */
static void decode_l4(pkt_t *p, const uint8_t *d, uint32_t avail, uint32_t l4len)
{
    if (p->proto == IPP_TCP) {
        if (avail < 20) {
            p->status = DEC_TRUNCATED;
            return;
        }
        if (l4len < 20) {
            p->status = DEC_MALFORMED;
            return;
        }
        p->sport = rd16(d);
        p->dport = rd16(d + 2);
        p->seq = rd32(d + 4);
        p->ack = rd32(d + 8);
        uint32_t doff = (uint32_t)(d[12] >> 4) * 4;
        p->tcp_flags = d[13];
        p->win = rd16(d + 14);
        if (doff < 20 || doff > l4len) {
            p->status = DEC_MALFORMED;
            return;
        }
        uint32_t optend = PA_MIN(doff, avail);
        if (optend > 20)
            parse_tcp_options(p, d + 20, optend - 20);
        p->l4_payload_len = l4len - doff;
        if (avail > doff) {
            p->payload = d + doff;
            p->payload_cap = PA_MIN(avail - doff, p->l4_payload_len);
        }
        p->l4_valid = 1;
    } else if (p->proto == IPP_UDP) {
        if (avail < 8) {
            p->status = DEC_TRUNCATED;
            return;
        }
        if (l4len < 8) {
            p->status = DEC_MALFORMED;
            return;
        }
        p->sport = rd16(d);
        p->dport = rd16(d + 2);
        uint32_t ulen = rd16(d + 4);
        if (ulen < 8 || ulen > l4len)  /* niespójna długość - użyj długości IP */
            ulen = l4len;
        p->l4_payload_len = ulen - 8;
        if (avail > 8) {
            p->payload = d + 8;
            p->payload_cap = PA_MIN(avail - 8, p->l4_payload_len);
        }
        p->l4_valid = 1;
    }
}

static void decode_ipv4(pkt_t *p, const uint8_t *d, uint32_t cap)
{
    if (cap < 20) {
        p->status = DEC_TRUNCATED;
        return;
    }
    if ((d[0] >> 4) != 4) {
        p->status = DEC_MALFORMED;
        return;
    }
    uint32_t ihl = (uint32_t)(d[0] & 0x0F) * 4;
    if (ihl < 20) {
        p->status = DEC_MALFORMED;
        return;
    }
    if (cap < ihl) {
        p->status = DEC_TRUNCATED;
        return;
    }
    uint32_t tot = rd16(d + 2);
    if (tot == 0)        /* TSO: długość 0 w pakietach przechwyconych lokalnie */
        tot = cap;
    if (tot < ihl) {
        p->status = DEC_MALFORMED;
        return;
    }
    p->ipver = 4;
    p->src.v = p->dst.v = 4;
    memcpy(p->src.a, d + 12, 4);
    memcpy(p->dst.a, d + 16, 4);
    p->ttl = d[8];
    p->proto = d[9];
    p->ip_total_len = tot;
    p->ip_cksum_bad = !ipv4_cksum_ok(d, ihl);
    if (cap < tot)
        p->snap_truncated = 1;

    uint16_t fo = rd16(d + 6);
    uint16_t offset = fo & 0x1FFF;
    if ((fo & 0x2000) || offset)
        p->frag = 1;
    if (offset)          /* kolejny fragment - brak nagłówka L4 */
        return;

    uint32_t l4len = tot - ihl;
    uint32_t avail = PA_MIN(cap - ihl, l4len);
    decode_l4(p, d + ihl, avail, l4len);
}

static void decode_ipv6(pkt_t *p, const uint8_t *d, uint32_t cap)
{
    if (cap < 40) {
        p->status = DEC_TRUNCATED;
        return;
    }
    if ((d[0] >> 4) != 6) {
        p->status = DEC_MALFORMED;
        return;
    }
    uint32_t plen = rd16(d + 4);
    uint8_t nh = d[6];
    p->ipver = 6;
    p->src.v = p->dst.v = 6;
    memcpy(p->src.a, d + 8, 16);
    memcpy(p->dst.a, d + 24, 16);
    p->ttl = d[7];
    uint32_t tot = plen ? 40 + plen : cap;   /* plen == 0: jumbogram / TSO */
    p->ip_total_len = tot;
    if (cap < tot)
        p->snap_truncated = 1;

    uint32_t off = 40;
    for (int guard = 0; guard < 8; guard++) {
        if (nh == 0 || nh == 43 || nh == 60) {          /* HBH, routing, dest */
            if (cap < off + 2) {
                p->proto = nh;
                p->status = DEC_TRUNCATED;
                return;
            }
            uint32_t hl = ((uint32_t)d[off + 1] + 1) * 8;
            nh = d[off];
            off += hl;
        } else if (nh == 44) {                           /* fragment */
            if (cap < off + 8) {
                p->proto = nh;
                p->status = DEC_TRUNCATED;
                return;
            }
            uint16_t fo = rd16(d + off + 2);
            p->frag = 1;
            nh = d[off];
            off += 8;
            if (fo & 0xFFF8) {     /* kolejny fragment - brak nagłówka L4 */
                p->proto = nh;
                return;
            }
        } else if (nh == 51) {                           /* AH */
            if (cap < off + 2) {
                p->proto = nh;
                p->status = DEC_TRUNCATED;
                return;
            }
            uint32_t hl = ((uint32_t)d[off + 1] + 2) * 4;
            nh = d[off];
            off += hl;
        } else {
            break;
        }
    }
    p->proto = nh;
    if (off > tot) {
        p->status = DEC_MALFORMED;
        return;
    }
    uint32_t l4len = tot - off;
    uint32_t lim = PA_MIN(cap, tot);
    uint32_t avail = lim > off ? lim - off : 0;
    decode_l4(p, d + off, avail, l4len);
}

int decode_packet(int dlt, double ts, uint32_t caplen, uint32_t wirelen,
                  const uint8_t *d, pkt_t *p)
{
    memset(p, 0, sizeof *p);
    p->ts = ts;
    p->caplen = caplen;
    p->wirelen = wirelen;
    p->wscale = -1;

    uint32_t off = 0;
    uint16_t et = 0;

    switch (dlt) {
    case DLT_EN10MB:
        if (caplen < 14)
            return p->status = DEC_TRUNCATED;
        et = rd16(d + 12);
        off = 14;
        while (et == ETH_VLAN || et == ETH_QINQ || et == ETH_QINQ2) {
            if (caplen < off + 4)
                return p->status = DEC_TRUNCATED;
            if (p->vlan_tags == 0)
                p->vlan_id = rd16(d + off) & 0x0FFF;
            p->vlan_tags++;
            et = rd16(d + off + 2);
            off += 4;
        }
        break;
    case DLT_LINUX_SLL:
        if (caplen < 16)
            return p->status = DEC_TRUNCATED;
        et = rd16(d + 14);
        off = 16;
        break;
#ifdef DLT_LINUX_SLL2
    case DLT_LINUX_SLL2:
        if (caplen < 20)
            return p->status = DEC_TRUNCATED;
        et = rd16(d);
        off = 20;
        break;
#endif
    case DLT_NULL:
    case DLT_LOOP: {
        if (caplen < 4)
            return p->status = DEC_TRUNCATED;
        uint32_t be = rd32(d);
        uint32_t le = (uint32_t)d[0] | ((uint32_t)d[1] << 8) |
                      ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
        off = 4;
        if (be == 2 || le == 2)
            et = ETH_IPV4;
        else if (be == 24 || be == 28 || be == 30 || le == 24 || le == 28 || le == 30)
            et = ETH_IPV6;
        break;
    }
    case DLT_RAW:
#if defined(DLT_IPV4) && defined(DLT_IPV6)
    case DLT_IPV4:
    case DLT_IPV6:
#endif
        if (caplen < 1)
            return p->status = DEC_TRUNCATED;
        if ((d[0] >> 4) == 4)
            et = ETH_IPV4;
        else if ((d[0] >> 4) == 6)
            et = ETH_IPV6;
        off = 0;
        break;
    default:
        return p->status = DEC_UNSUPPORTED_LINK;
    }

    p->ethertype = et;
    if (et == ETH_IPV4)
        decode_ipv4(p, d + off, caplen - off);
    else if (et == ETH_IPV6)
        decode_ipv6(p, d + off, caplen - off);
    else
        p->status = DEC_NOT_IP;
    return p->status;
}
