/*
 * common.h - wspólne typy, makra i funkcje pomocnicze narzędzia pcapanalyzer.
 */
#ifndef PA_COMMON_H
#define PA_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define PA_NAME    "pcapanalyzer"
#define PA_VERSION "1.0.0"

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define PA_MIN(a, b) ((a) < (b) ? (a) : (b))
#define PA_MAX(a, b) ((a) > (b) ? (a) : (b))

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* Numery protokołów IP używane w programie. */
#define IPP_ICMP  1
#define IPP_TCP   6
#define IPP_UDP   17
#define IPP_ICMP6 58

#define IPSTR_LEN 48

/* Adres IPv4/IPv6. Nieużywane bajty są zawsze wyzerowane, dzięki czemu
 * strukturę można haszować i porównywać bajt po bajcie. */
typedef struct {
    uint8_t v;      /* 4 lub 6; 0 = brak adresu */
    uint8_t a[16];  /* IPv4 zajmuje pierwsze 4 bajty */
} ip_addr_t;

static inline uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static inline uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Alokacja z obsługą braku pamięci (kończy program). */
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t sz);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);

int ip_cmp(const ip_addr_t *x, const ip_addr_t *y);
const char *ip_str(const ip_addr_t *ip, char *buf, size_t n);
uint32_t fnv1a(const void *data, size_t n);

/* Formatowanie liczb (polski separator dziesiętny - przecinek). */
void fmt_count(uint64_t v, char *buf, size_t n);     /* 1 234 567     */
void fmt_bytes(double v, char *buf, size_t n);       /* 1,23 MB       */
void fmt_bitrate(double bps, char *buf, size_t n);   /* 12,5 Mb/s     */
void fmt_duration(double s, char *buf, size_t n);    /* 1,52 s        */
void fmt_compact(double v, char *buf, size_t n);     /* 1,2k          */
void fmt_percent(double frac, char *buf, size_t n);  /* 12,5%         */
void fmt_fixed(double v, int decimals, char *buf, size_t n);
void fmt_timestamp(double ts, char *buf, size_t n);  /* UTC           */

const char *service_name(int proto, uint16_t port);
void fmt_service(int proto, uint16_t port, char *buf, size_t n);
const char *proto_name(int proto);

int mkdir_p(const char *path);
void sappend(char *buf, size_t n, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

#endif
