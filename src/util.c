/*
 * util.c - funkcje pomocnicze: alokacja, adresy IP, formatowanie liczb,
 * tablica nazw usług, tworzenie katalogów.
 */
#include "common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

static void out_of_memory(void)
{
    fprintf(stderr, PA_NAME ": brak pamięci\n");
    exit(1);
}

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p)
        out_of_memory();
    return p;
}

void *xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p)
        out_of_memory();
    return p;
}

void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q)
        out_of_memory();
    return q;
}

char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *d = xmalloc(n);
    memcpy(d, s, n);
    return d;
}

int ip_cmp(const ip_addr_t *x, const ip_addr_t *y)
{
    if (x->v != y->v)
        return x->v < y->v ? -1 : 1;
    return memcmp(x->a, y->a, x->v == 4 ? 4 : 16);
}

const char *ip_str(const ip_addr_t *ip, char *buf, size_t n)
{
    if (ip->v == 4) {
        if (!inet_ntop(AF_INET, ip->a, buf, (socklen_t)n))
            snprintf(buf, n, "?");
    } else if (ip->v == 6) {
        if (!inet_ntop(AF_INET6, ip->a, buf, (socklen_t)n))
            snprintf(buf, n, "?");
    } else {
        snprintf(buf, n, "-");
    }
    return buf;
}

uint32_t fnv1a(const void *data, size_t n)
{
    const uint8_t *p = data;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

/* Zamiana kropki dziesiętnej na przecinek (konwencja polska). */
static void to_comma(char *s)
{
    for (; *s; s++)
        if (*s == '.')
            *s = ',';
}

void fmt_count(uint64_t v, char *buf, size_t n)
{
    char tmp[32];
    snprintf(tmp, sizeof tmp, "%llu", (unsigned long long)v);
    size_t len = strlen(tmp), o = 0;
    for (size_t i = 0; i < len && o + 2 < n; i++) {
        if (i > 0 && (len - i) % 3 == 0)
            buf[o++] = ' ';
        buf[o++] = tmp[i];
    }
    buf[o] = '\0';
}

static void fmt_scaled(double v, const char *const *units, int nunits,
                       char *buf, size_t n)
{
    int i = 0;
    while (fabs(v) >= 1000.0 && i < nunits - 1) {
        v /= 1000.0;
        i++;
    }
    if (i == 0 || fabs(v - round(v)) < 1e-9)   /* wartości całkowite bez ",00" */
        snprintf(buf, n, "%.0f %s", v, units[i]);
    else if (fabs(v) < 10)
        snprintf(buf, n, "%.2f %s", v, units[i]);
    else if (fabs(v) < 100)
        snprintf(buf, n, "%.1f %s", v, units[i]);
    else
        snprintf(buf, n, "%.0f %s", v, units[i]);
    to_comma(buf);
}

void fmt_bytes(double v, char *buf, size_t n)
{
    static const char *const u[] = {"B", "kB", "MB", "GB", "TB"};
    fmt_scaled(v, u, 5, buf, n);
}

void fmt_bitrate(double bps, char *buf, size_t n)
{
    static const char *const u[] = {"b/s", "kb/s", "Mb/s", "Gb/s", "Tb/s"};
    fmt_scaled(bps, u, 5, buf, n);
}

void fmt_duration(double s, char *buf, size_t n)
{
    if (s < 0)
        s = 0;
    if (s < 0.001)
        snprintf(buf, n, "%.0f µs", s * 1e6);
    else if (s < 1.0)
        snprintf(buf, n, "%.1f ms", s * 1e3);
    else if (s < 60.0)
        snprintf(buf, n, "%.2f s", s);
    else if (s < 3600.0)
        snprintf(buf, n, "%d min %02d s", (int)(s / 60), (int)fmod(s, 60.0));
    else
        snprintf(buf, n, "%d h %02d min", (int)(s / 3600),
                 (int)fmod(s / 60.0, 60.0));
    to_comma(buf);
}

/* Usuwa zbędne ",0" przed przyrostkiem, np. "2,0k" -> "2k". */
static void strip_zero_decimal(char *s)
{
    char *p = strstr(s, ".0");
    if (p && !(p[2] >= '0' && p[2] <= '9'))
        memmove(p, p + 2, strlen(p + 2) + 1);
}

void fmt_compact(double v, char *buf, size_t n)
{
    double a = fabs(v);
    if (a >= 1e9)
        snprintf(buf, n, "%.1fG", v / 1e9);
    else if (a >= 1e6)
        snprintf(buf, n, "%.1fM", v / 1e6);
    else if (a >= 1e4)
        snprintf(buf, n, "%.1fk", v / 1e3);
    else if (a == floor(a))
        snprintf(buf, n, "%.0f", v);
    else if (a >= 10)
        snprintf(buf, n, "%.0f", v);
    else if (a >= 1)
        snprintf(buf, n, "%.1f", v);
    else if (a >= 0.01)
        snprintf(buf, n, "%.2f", v);
    else
        snprintf(buf, n, "%g", v);
    strip_zero_decimal(buf);
    to_comma(buf);
}

void fmt_percent(double frac, char *buf, size_t n)
{
    double p = frac * 100.0;
    if (p == 0)
        snprintf(buf, n, "0%%");
    else if (p < 0.1)
        snprintf(buf, n, "%.2f%%", p);
    else if (p < 10)
        snprintf(buf, n, "%.1f%%", p);
    else
        snprintf(buf, n, "%.0f%%", p);
    to_comma(buf);
}

void fmt_fixed(double v, int decimals, char *buf, size_t n)
{
    snprintf(buf, n, "%.*f", decimals, v);
    to_comma(buf);
}

void fmt_timestamp(double ts, char *buf, size_t n)
{
    time_t t = (time_t)ts;
    struct tm tm;
    if (!gmtime_r(&t, &tm)) {
        snprintf(buf, n, "-");
        return;
    }
    char tmp[64];
    strftime(tmp, sizeof tmp, "%Y-%m-%d %H:%M:%S", &tm);
    int ms = (int)((ts - floor(ts)) * 1000.0);
    snprintf(buf, n, "%s,%03d UTC", tmp, ms);
}

typedef struct {
    uint16_t port;
    uint8_t tcp, udp;
    const char *name;
} svc_t;

static const svc_t SERVICES[] = {
    {20, 1, 0, "ftp-data"},  {21, 1, 0, "ftp"},       {22, 1, 0, "ssh"},
    {23, 1, 0, "telnet"},    {25, 1, 0, "smtp"},      {53, 1, 1, "dns"},
    {67, 0, 1, "dhcp"},      {68, 0, 1, "dhcp"},      {69, 0, 1, "tftp"},
    {80, 1, 0, "http"},      {110, 1, 0, "pop3"},     {123, 0, 1, "ntp"},
    {135, 1, 0, "msrpc"},    {137, 0, 1, "netbios-ns"}, {138, 0, 1, "netbios-dgm"},
    {139, 1, 0, "netbios"},  {143, 1, 0, "imap"},     {161, 0, 1, "snmp"},
    {162, 0, 1, "snmptrap"}, {389, 1, 1, "ldap"},     {443, 1, 1, "https/quic"},
    {445, 1, 0, "smb"},      {465, 1, 0, "smtps"},    {500, 0, 1, "isakmp"},
    {514, 0, 1, "syslog"},   {587, 1, 0, "submission"}, {636, 1, 0, "ldaps"},
    {853, 1, 1, "dns-tls"},  {993, 1, 0, "imaps"},    {995, 1, 0, "pop3s"},
    {1194, 1, 1, "openvpn"}, {1433, 1, 0, "mssql"},   {1883, 1, 0, "mqtt"},
    {1900, 0, 1, "ssdp"},    {3306, 1, 0, "mysql"},   {3389, 1, 1, "rdp"},
    {4500, 0, 1, "ipsec-nat"}, {5060, 1, 1, "sip"},   {5353, 0, 1, "mdns"},
    {5432, 1, 0, "postgresql"}, {5900, 1, 0, "vnc"},  {6379, 1, 0, "redis"},
    {8080, 1, 0, "http-alt"}, {8443, 1, 0, "https-alt"}, {9200, 1, 0, "elasticsearch"},
    {27017, 1, 0, "mongodb"},
};

const char *service_name(int proto, uint16_t port)
{
    for (size_t i = 0; i < ARRAY_LEN(SERVICES); i++) {
        const svc_t *s = &SERVICES[i];
        if (s->port != port)
            continue;
        if ((proto == IPP_TCP && s->tcp) || (proto == IPP_UDP && s->udp)) {
            if (port == 443)
                return proto == IPP_TCP ? "https" : "quic";
            return s->name;
        }
    }
    return NULL;
}

const char *proto_name(int proto)
{
    switch (proto) {
    case IPP_TCP:   return "TCP";
    case IPP_UDP:   return "UDP";
    case IPP_ICMP:  return "ICMP";
    case IPP_ICMP6: return "ICMPv6";
    default:        return "IP";
    }
}

void fmt_service(int proto, uint16_t port, char *buf, size_t n)
{
    const char *s = service_name(proto, port);
    const char *p = proto == IPP_TCP ? "tcp" : proto == IPP_UDP ? "udp" : "ip";
    if (s)
        snprintf(buf, n, "%s/%u (%s)", p, (unsigned)port, s);
    else
        snprintf(buf, n, "%s/%u", p, (unsigned)port);
}

int mkdir_p(const char *path)
{
    char tmp[4096];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof tmp) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(tmp, path, len + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

void sappend(char *buf, size_t n, const char *fmt, ...)
{
    size_t len = strlen(buf);
    if (len + 1 >= n)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf + len, n - len, fmt, ap);
    va_end(ap);
}
