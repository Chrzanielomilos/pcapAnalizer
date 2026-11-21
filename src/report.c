/*
 * report.c - składanie raportu PDF.
 *
 * Prosty silnik układu strony: akapity z zawijaniem wierszy (UTF-8),
 * nagłówki z zakładkami PDF, listy punktowane, tabele z zawijaniem
 * tekstu w komórkach i powtarzaniem nagłówka po podziale strony oraz
 * wektorowe wykresy (te same definicje co pliki PNG).
 */
#include "report.h"
#include "charts.h"

#include <cairo-pdf.h>
#include <cairo.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PAGE_W   595.276
#define PAGE_H   841.890
#define MARGIN_L 56.0
#define MARGIN_R 56.0
#define MARGIN_T 64.0
#define MARGIN_B 62.0
#define CONTENT_W (PAGE_W - MARGIN_L - MARGIN_R)

#define FS_BODY 9.4
#define LH_BODY 13.4

/* Logiczny rozmiar wykresu w raporcie (skalowany do szerokości strony). */
#define FIG_LW 640.0
#define FIG_LH 360.0

#define COL_ZEBRA 0xf6f6f3

#if CAIRO_VERSION >= CAIRO_VERSION_ENCODE(1, 16, 0)
#define HAVE_PDF_OUTLINE 1
#endif

typedef struct {
    cairo_surface_t  *surf;
    cairo_t          *cr;
    double            y;
    int               page;
    int               fig_no, tab_no;
    int               outline_parent;
    const analysis_t *a;
    const char       *footer;     /* tekst stopki                         */
    char              header[300];
} doc_t;

/* ======================= wiersze tekstu ======================= */

typedef struct {
    char **v;
    int    n, cap;
} lines_t;

static void lines_push(lines_t *l, const char *s, size_t len)
{
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 16;
        l->v = xrealloc(l->v, (size_t)l->cap * sizeof *l->v);
    }
    char *t = xmalloc(len + 1);
    if (len)
        memcpy(t, s, len);
    t[len] = '\0';
    l->v[l->n++] = t;
}

static void lines_free(lines_t *l)
{
    for (int i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
    memset(l, 0, sizeof *l);
}

/* Zawija jeden akapit (bez znaków nowego wiersza) do szerokości maxw. */
static void wrap_par(cairo_t *cr, const char *p, size_t len, double maxw, lines_t *out)
{
    char line[2048], cand[2048];
    size_t ll = 0, i = 0;
    int any = 0;
    line[0] = '\0';

    while (i < len) {
        while (i < len && p[i] == ' ')
            i++;
        if (i >= len)
            break;
        size_t ws = i;
        while (i < len && p[i] != ' ')
            i++;
        size_t wl = PA_MIN(i - ws, (size_t)900);
        any = 1;

        if (ll && ll + 1 + wl < sizeof cand) {
            memcpy(cand, line, ll);
            cand[ll] = ' ';
            memcpy(cand + ll + 1, p + ws, wl);
            cand[ll + 1 + wl] = '\0';
            if (text_width(cr, cand) <= maxw) {
                memcpy(line, cand, ll + 2 + wl);
                ll = ll + 1 + wl;
                continue;
            }
        }
        if (ll) {
            lines_push(out, line, ll);
            ll = 0;
        }
        memcpy(cand, p + ws, wl);
        cand[wl] = '\0';
        if (text_width(cr, cand) <= maxw) {
            memcpy(line, cand, wl + 1);
            ll = wl;
            continue;
        }
        /* słowo szersze niż wiersz - łamanie po znakach UTF-8 */
        size_t s = 0;
        while (s < wl) {
            size_t e = s, last_ok = s;
            while (e < wl) {
                size_t nx = e + 1;
                while (nx < wl && ((unsigned char)p[ws + nx] & 0xC0) == 0x80)
                    nx++;
                memcpy(cand, p + ws + s, nx - s);
                cand[nx - s] = '\0';
                if (text_width(cr, cand) > maxw && last_ok > s)
                    break;
                last_ok = nx;
                e = nx;
            }
            if (last_ok >= wl) {
                memcpy(line, p + ws + s, wl - s);
                ll = wl - s;
                line[ll] = '\0';
                break;
            }
            lines_push(out, p + ws + s, last_ok - s);
            s = last_ok;
        }
    }
    if (ll || !any)
        lines_push(out, line, ll);
}

static void wrap_text(cairo_t *cr, const char *text, double maxw, lines_t *out)
{
    const char *p = text;
    for (;;) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        wrap_par(cr, p, len, maxw, out);
        if (!nl)
            break;
        p = nl + 1;
    }
}

/* ======================= strony ======================= */

static void doc_page_begin(doc_t *d)
{
    d->page++;
    d->y = MARGIN_T;
    if (d->page > 1) {
        cairo_t *cr = d->cr;
        char buf[300];
        use_font(cr, 7.5, 0);
        set_rgb(cr, COL_MUTED);
        fit_text(cr, d->header, CONTENT_W, buf, sizeof buf);
        cairo_move_to(cr, MARGIN_L, 38);
        cairo_show_text(cr, buf);
        set_rgb(cr, COL_GRID);
        cairo_set_line_width(cr, 0.6);
        cairo_move_to(cr, MARGIN_L, 45);
        cairo_line_to(cr, PAGE_W - MARGIN_R, 45);
        cairo_stroke(cr);
    }
}

static void doc_footer(doc_t *d)
{
    cairo_t *cr = d->cr;
    char buf[64];
    set_rgb(cr, COL_GRID);
    cairo_set_line_width(cr, 0.6);
    cairo_move_to(cr, MARGIN_L, PAGE_H - 44);
    cairo_line_to(cr, PAGE_W - MARGIN_R, PAGE_H - 44);
    cairo_stroke(cr);
    use_font(cr, 7.5, 0);
    set_rgb(cr, COL_MUTED);
    cairo_move_to(cr, MARGIN_L, PAGE_H - 32);
    cairo_show_text(cr, d->footer);
    snprintf(buf, sizeof buf, "Strona %d", d->page);
    cairo_move_to(cr, PAGE_W - MARGIN_R - text_width(cr, buf), PAGE_H - 32);
    cairo_show_text(cr, buf);
}

static void doc_new_page(doc_t *d)
{
    doc_footer(d);
    cairo_show_page(d->cr);
    doc_page_begin(d);
}

static void doc_need(doc_t *d, double h)
{
    if (d->y + h > PAGE_H - MARGIN_B)
        doc_new_page(d);
}

static void doc_outline(doc_t *d, int level, const char *text, double y)
{
#ifdef HAVE_PDF_OUTLINE
    char attr[96];
    snprintf(attr, sizeof attr, "page=%d pos=[%.1f %.1f]", d->page, MARGIN_L, y);
    int parent = level == 1 ? CAIRO_PDF_OUTLINE_ROOT : d->outline_parent;
    int id = cairo_pdf_surface_add_outline(d->surf, parent, text, attr,
                                           level == 1 ? CAIRO_PDF_OUTLINE_FLAG_OPEN
                                                      : (cairo_pdf_outline_flags_t)0);
    if (level == 1)
        d->outline_parent = id;
#else
    (void)d; (void)level; (void)text; (void)y;
#endif
}

/* ======================= elementy tekstowe ======================= */

static void doc_text(doc_t *d, const char *text, double size, int bold, uint32_t color,
                     double indent, double lh)
{
    cairo_t *cr = d->cr;
    lines_t L = {0};
    use_font(cr, size, bold);
    wrap_text(cr, text, CONTENT_W - indent, &L);
    for (int i = 0; i < L.n; i++) {
        doc_need(d, lh);
        use_font(cr, size, bold);
        set_rgb(cr, color);
        cairo_move_to(cr, MARGIN_L + indent, d->y + size);
        cairo_show_text(cr, L.v[i]);
        d->y += lh;
    }
    lines_free(&L);
}

static void doc_para(doc_t *d, const char *text)
{
    doc_text(d, text, FS_BODY, 0, COL_INK, 0, LH_BODY);
    d->y += 5;
}

static __attribute__((format(printf, 2, 3)))
void doc_paraf(doc_t *d, const char *fmt, ...)
{
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    doc_para(d, buf);
}

static void doc_bullet(doc_t *d, const char *text)
{
    cairo_t *cr = d->cr;
    lines_t L = {0};
    use_font(cr, FS_BODY, 0);
    wrap_text(cr, text, CONTENT_W - 14, &L);
    for (int i = 0; i < L.n; i++) {
        doc_need(d, LH_BODY);
        use_font(cr, FS_BODY, 0);
        set_rgb(cr, COL_INK);
        if (i == 0) {
            cairo_move_to(cr, MARGIN_L + 3, d->y + FS_BODY);
            cairo_show_text(cr, "•");
        }
        cairo_move_to(cr, MARGIN_L + 14, d->y + FS_BODY);
        cairo_show_text(cr, L.v[i]);
        d->y += LH_BODY;
    }
    d->y += 2.5;
    lines_free(&L);
}

static void doc_heading(doc_t *d, int level, const char *text)
{
    cairo_t *cr = d->cr;
    double size = level == 1 ? 16 : level == 2 ? 11.5 : 10;
    if (level == 1 && d->y > MARGIN_T + 1)
        doc_new_page(d);
    else if (d->y > MARGIN_T + 1)
        d->y += 8;
    doc_need(d, size + 70);          /* nagłówek nie może zostać sam na dole strony */
    doc_outline(d, level, text, d->y);
    use_font(cr, size, 1);
    set_rgb(cr, COL_INK);
    cairo_move_to(cr, MARGIN_L, d->y + size);
    cairo_show_text(cr, text);
    d->y += size + (level == 1 ? 8 : 6);
    if (level == 1) {
        set_rgb(cr, COL_GRID);
        cairo_set_line_width(cr, 0.8);
        cairo_move_to(cr, MARGIN_L, d->y);
        cairo_line_to(cr, PAGE_W - MARGIN_R, d->y);
        cairo_stroke(cr);
        d->y += 12;
    }
}

/* ======================= znaczniki ważności ======================= */

static uint32_t sev_color(severity_t s)
{
    switch (s) {
    case SEV_HIGH:   return COL_CRITICAL;
    case SEV_MEDIUM: return COL_SERIOUS;
    case SEV_LOW:    return COL_WARNING;
    default:         return COL_MUTED;
    }
}

static void rrect(cairo_t *cr, double x, double y, double w, double h, double r)
{
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r, r, -M_PI / 2, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0, M_PI / 2);
    cairo_arc(cr, x + r, y + h - r, r, M_PI / 2, M_PI);
    cairo_arc(cr, x + r, y + r, r, M_PI, 1.5 * M_PI);
    cairo_close_path(cr);
}

/* Znacznik: kolor statusu + etykieta tekstowa (kolor nigdy nie występuje sam). */
static double draw_badge(cairo_t *cr, double x, double ytop, const char *label,
                         uint32_t color)
{
    use_font(cr, 7.2, 1);
    double w = text_width(cr, label) + 10;
    rrect(cr, x, ytop, w, 11.5, 3);
    set_rgb(cr, color);
    cairo_fill(cr);
    set_rgb(cr, color == COL_WARNING ? COL_INK : 0xffffff);
    cairo_move_to(cr, x + 5, ytop + 8.4);
    cairo_show_text(cr, label);
    return w;
}

/* Wiersz z znacznikiem ważności i zawijanym tekstem. */
static void doc_badge_line(doc_t *d, severity_t sev, const char *text)
{
    cairo_t *cr = d->cr;
    use_font(cr, 7.2, 1);
    double bw = text_width(cr, severity_name(sev)) + 10;
    double indent = 56;
    lines_t L = {0};
    use_font(cr, FS_BODY, 0);
    wrap_text(cr, text, CONTENT_W - indent, &L);
    for (int i = 0; i < L.n; i++) {
        doc_need(d, LH_BODY + 1);
        if (i == 0)
            draw_badge(cr, MARGIN_L + (indent - 6 - bw), d->y + 1, severity_name(sev),
                       sev_color(sev));
        use_font(cr, FS_BODY, 0);
        set_rgb(cr, COL_INK);
        cairo_move_to(cr, MARGIN_L + indent, d->y + FS_BODY);
        cairo_show_text(cr, L.v[i]);
        d->y += LH_BODY + 1;
    }
    d->y += 2;
    lines_free(&L);
}

/* ======================= tabele ======================= */

typedef struct {
    int                ncol;
    const char *const *hdr;     /* NULL = bez nagłówka                */
    const double      *w;       /* udziały szerokości kolumn (suma 1) */
    const char        *align;   /* 'l' / 'r' dla każdej kolumny        */
} tspec_t;

typedef struct {
    char **c;
    int    n, cap;
} cells_t;

static __attribute__((format(printf, 2, 3)))
void cell(cells_t *cb, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (cb->n == cb->cap) {
        cb->cap = cb->cap ? cb->cap * 2 : 32;
        cb->c = xrealloc(cb->c, (size_t)cb->cap * sizeof *cb->c);
    }
    cb->c[cb->n++] = xstrdup(buf);
}

static void cells_free(cells_t *cb)
{
    for (int i = 0; i < cb->n; i++)
        free(cb->c[i]);
    free(cb->c);
    memset(cb, 0, sizeof *cb);
}

#define T_FS  8.0
#define T_LH  10.6
#define T_PAD 5.0

static void table_header(doc_t *d, const tspec_t *t, const double *x)
{
    cairo_t *cr = d->cr;
    double rh = T_LH + 2 * T_PAD;
    set_rgb(cr, COL_PANEL);
    cairo_rectangle(cr, MARGIN_L, d->y, CONTENT_W, rh);
    cairo_fill(cr);
    use_font(cr, T_FS, 1);
    set_rgb(cr, COL_INK);
    for (int j = 0; j < t->ncol; j++) {
        char buf[256];
        double cw = x[j + 1] - x[j] - 2 * T_PAD;
        fit_text(cr, t->hdr[j], cw, buf, sizeof buf);
        double tx = t->align[j] == 'r' ? x[j + 1] - T_PAD - text_width(cr, buf) : x[j] + T_PAD;
        cairo_move_to(cr, tx, d->y + T_PAD + T_FS);
        cairo_show_text(cr, buf);
    }
    d->y += rh;
}

static void doc_table(doc_t *d, const tspec_t *t, const cells_t *cb, const char *caption)
{
    cairo_t *cr = d->cr;
    int nrows = t->ncol ? cb->n / t->ncol : 0;
    double x[17];
    x[0] = MARGIN_L;
    for (int j = 0; j < t->ncol && j < 16; j++)
        x[j + 1] = x[j] + t->w[j] * CONTENT_W;

    if (caption) {
        char buf[300];
        d->tab_no++;
        snprintf(buf, sizeof buf, "Tabela %d. %s", d->tab_no, caption);
        doc_need(d, 70);
        use_font(cr, 8.5, 1);
        set_rgb(cr, COL_INK2);
        cairo_move_to(cr, MARGIN_L, d->y + 8.5);
        cairo_show_text(cr, buf);
        d->y += 15;
    }
    if (t->hdr) {
        doc_need(d, 3 * (T_LH + 2 * T_PAD));
        table_header(d, t, x);
    }

    for (int r = 0; r < nrows; r++) {
        lines_t L[16];
        int maxl = 1;
        memset(L, 0, sizeof L);
        for (int j = 0; j < t->ncol && j < 16; j++) {
            use_font(cr, T_FS, t->hdr == NULL && j == 0);
            wrap_text(cr, cb->c[r * t->ncol + j], x[j + 1] - x[j] - 2 * T_PAD, &L[j]);
            if (L[j].n > maxl)
                maxl = L[j].n;
        }
        double rh = maxl * T_LH + 2 * T_PAD - 2;
        if (d->y + rh > PAGE_H - MARGIN_B) {
            doc_new_page(d);
            if (t->hdr)
                table_header(d, t, x);
        }
        if (r % 2 == 1) {
            set_rgb(cr, COL_ZEBRA);
            cairo_rectangle(cr, MARGIN_L, d->y, CONTENT_W, rh);
            cairo_fill(cr);
        }
        for (int j = 0; j < t->ncol && j < 16; j++) {
            use_font(cr, T_FS, t->hdr == NULL && j == 0);
            set_rgb(cr, (t->hdr == NULL && j == 0) ? COL_INK2 : COL_INK);
            for (int k = 0; k < L[j].n; k++) {
                double tx = t->align[j] == 'r'
                    ? x[j + 1] - T_PAD - text_width(cr, L[j].v[k]) : x[j] + T_PAD;
                cairo_move_to(cr, tx, d->y + T_PAD - 1 + T_FS + k * T_LH);
                cairo_show_text(cr, L[j].v[k]);
            }
            lines_free(&L[j]);
        }
        d->y += rh;
    }
    set_rgb(cr, COL_AXIS);
    cairo_set_line_width(cr, 0.7);
    cairo_move_to(cr, MARGIN_L, d->y);
    cairo_line_to(cr, PAGE_W - MARGIN_R, d->y);
    cairo_stroke(cr);
    d->y += 14;
}

/* Tabela dwukolumnowa "miara - wartość". */
static void doc_kv_table(doc_t *d, const cells_t *cb, const char *caption)
{
    static const char *const hdr[] = {"Miara", "Wartość"};
    static const double w[] = {0.52, 0.48};
    tspec_t t = {2, hdr, w, "lr"};
    doc_table(d, &t, cb, caption);
}

/* ======================= wykresy ======================= */

static void doc_caption(doc_t *d, const char *text)
{
    doc_text(d, text, 8.4, 1, COL_INK2, 0, 11.5);
    d->y += 2;
}

static void doc_figure(doc_t *d, const figure_t *f, int png_written)
{
    cairo_t *cr = d->cr;
    double s = CONTENT_W / FIG_LW, h = FIG_LH * s;
    doc_need(d, h + 40);

    cairo_save(cr);
    cairo_translate(cr, MARGIN_L, d->y);
    cairo_scale(cr, s, s);
    chart_render(cr, &f->chart, FIG_LW, FIG_LH);
    cairo_restore(cr);
    set_rgb(cr, COL_GRID);
    cairo_set_line_width(cr, 0.6);
    cairo_rectangle(cr, MARGIN_L, d->y, CONTENT_W, h);
    cairo_stroke(cr);
    d->y += h + 7;

    char buf[400];
    d->fig_no++;
    if (png_written)
        snprintf(buf, sizeof buf, "Rys. %d. %s (plik %s)", d->fig_no, f->caption, f->file);
    else
        snprintf(buf, sizeof buf, "Rys. %d. %s", d->fig_no, f->caption);
    doc_caption(d, buf);
    doc_text(d, f->desc, 8.6, 0, COL_INK2, 0, 11.8);
    d->y += 14;
}

static void draw_tile(cairo_t *cr, double x, double y, double w, double h,
                      const char *label, const char *value, const char *sub)
{
    char buf[128];
    rrect(cr, x, y, w, h, 6);
    set_rgb(cr, COL_SURFACE);
    cairo_fill_preserve(cr);
    set_rgb(cr, COL_GRID);
    cairo_set_line_width(cr, 0.8);
    cairo_stroke(cr);
    use_font(cr, 7.8, 0);
    set_rgb(cr, COL_INK2);
    cairo_move_to(cr, x + 11, y + 17);
    cairo_show_text(cr, label);
    use_font(cr, 17, 1);
    set_rgb(cr, COL_INK);
    fit_text(cr, value, w - 22, buf, sizeof buf);
    cairo_move_to(cr, x + 11, y + 40);
    cairo_show_text(cr, buf);
    if (sub) {
        use_font(cr, 7.2, 0);
        set_rgb(cr, COL_MUTED);
        fit_text(cr, sub, w - 22, buf, sizeof buf);
        cairo_move_to(cr, x + 11, y + 54);
        cairo_show_text(cr, buf);
    }
}

/* ======================= pomocnicze obliczenia ======================= */

static void peak_rates(const analysis_t *a, double *bps, double *pps, double *at)
{
    size_t n;
    double w;
    ts_bin_t *b = ts_rebin(&a->ts, 1000000, 1.0, &n, &w);
    *bps = *pps = *at = 0;
    for (size_t i = 0; i < n; i++) {
        double bytes = (double)(b[i].bytes[0] + b[i].bytes[1] + b[i].bytes[2]);
        if (bytes * 8.0 / w > *bps) {
            *bps = bytes * 8.0 / w;
            *at = (double)i * w;
        }
        double p = (double)ts_bin_pkts(&b[i]) / w;
        if (p > *pps)
            *pps = p;
    }
    free(b);
}

static double ratio(uint64_t x, uint64_t total)
{
    return total ? (double)x / (double)total : 0.0;
}

static const char *assessment(severity_t s, int nonInfo)
{
    if (!nonInfo)
        return "Nie wykryto nieprawidłowości wymagających uwagi.";
    switch (s) {
    case SEV_HIGH:
        return "Wykryto nieprawidłowości o wysokim priorytecie – pilna weryfikacja.";
    case SEV_MEDIUM:
        return "Wykryto nieprawidłowości o średnim priorytecie – zalecana analiza.";
    default:
        return "Wykryto drobne nieprawidłowości o niskim priorytecie.";
    }
}

/* ======================= sekcje raportu ======================= */

static void sec_title(doc_t *d)
{
    const analysis_t *a = d->a;
    cairo_t *cr = d->cr;
    char b1[64], b2[64], b3[64];

    d->y = 120;
    use_font(cr, 9, 1);
    set_rgb(cr, COL_TCP);
    cairo_move_to(cr, MARGIN_L, d->y);
    cairo_show_text(cr, "RAPORT ANALIZY RUCHU SIECIOWEGO");
    d->y += 34;
    use_font(cr, 26, 1);
    set_rgb(cr, COL_INK);
    cairo_move_to(cr, MARGIN_L, d->y);
    cairo_show_text(cr, "Komunikacja TCP i UDP");
    d->y += 24;
    use_font(cr, 12.5, 0);
    set_rgb(cr, COL_INK2);
    fit_text(cr, a->name, CONTENT_W, b1, sizeof b1);
    cairo_move_to(cr, MARGIN_L, d->y);
    cairo_show_text(cr, b1);
    d->y += 30;

    /* kafelki z kluczowymi wartościami */
    double gap = 10, tw = (CONTENT_W - 2 * gap) / 3, th = 64;
    char v[6][64], s[6][96];
    fmt_count(a->g.pkts, v[0], sizeof v[0]);
    snprintf(s[0], sizeof s[0], "IPv4: %llu · IPv6: %llu",
             (unsigned long long)a->g.ipv4, (unsigned long long)a->g.ipv6);
    fmt_bytes((double)a->g.bytes, v[1], sizeof v[1]);
    fmt_duration(a->duration, b1, sizeof b1);
    snprintf(s[1], sizeof s[1], "w czasie %s", b1);
    fmt_bitrate(a->duration > 0 ? (double)a->g.bytes * 8.0 / a->duration : 0, v[2], sizeof v[2]);
    double pb, pp, pt;
    peak_rates(a, &pb, &pp, &pt);
    fmt_bitrate(pb, b2, sizeof b2);
    snprintf(s[2], sizeof s[2], "maksimum (1 s): %s", b2);
    fmt_count(a->tcp_flows, v[3], sizeof v[3]);
    fmt_count(a->tcp_established, b3, sizeof b3);
    snprintf(s[3], sizeof s[3], "nawiązanych połączeń: %s", b3);
    fmt_count(a->udp_flows, v[4], sizeof v[4]);
    fmt_count(a->dns.queries, b3, sizeof b3);
    snprintf(s[4], sizeof s[4], "zapytań DNS: %s", b3);
    snprintf(v[5], sizeof v[5], "%zu", a->nanom);
    snprintf(s[5], sizeof s[5], "wysokie: %d · średnie: %d · niskie: %d",
             analysis_count_severity(a, SEV_HIGH), analysis_count_severity(a, SEV_MEDIUM),
             analysis_count_severity(a, SEV_LOW));
    static const char *const lab[6] = {"Pakiety", "Wolumen", "Średnia przepływność",
                                       "Przepływy TCP", "Przepływy UDP", "Nieprawidłowości"};
    for (int i = 0; i < 6; i++)
        draw_tile(cr, MARGIN_L + (i % 3) * (tw + gap), d->y + (i / 3) * (th + gap), tw, th,
                  lab[i], v[i], s[i]);
    d->y += 2 * th + gap + 22;

    /* ocena ogólna */
    severity_t ms = analysis_max_severity(a);
    int non_info = a->nanom > (size_t)analysis_count_severity(a, SEV_INFO);
    uint32_t col = non_info ? sev_color(ms) : COL_GOOD;
    const char *lbl = non_info ? severity_name(ms) : "OK";
    rrect(cr, MARGIN_L, d->y, CONTENT_W, 46, 6);
    set_rgb(cr, COL_SURFACE);
    cairo_fill_preserve(cr);
    set_rgb(cr, COL_GRID);
    cairo_set_line_width(cr, 0.8);
    cairo_stroke(cr);
    set_rgb(cr, col);
    cairo_rectangle(cr, MARGIN_L, d->y + 6, 4, 34);
    cairo_fill(cr);
    use_font(cr, 8, 0);
    set_rgb(cr, COL_INK2);
    cairo_move_to(cr, MARGIN_L + 16, d->y + 18);
    cairo_show_text(cr, "Ocena ogólna");
    double bwid = draw_badge(cr, MARGIN_L + 16, d->y + 25, lbl, col);
    char ab[160];
    use_font(cr, 8.8, 1);
    set_rgb(cr, COL_INK);
    fit_text(cr, assessment(ms, non_info), CONTENT_W - bwid - 36, ab, sizeof ab);
    cairo_move_to(cr, MARGIN_L + 24 + bwid, d->y + 34);
    cairo_show_text(cr, ab);
    d->y += 66;

    /* metadane */
    cells_t cb = {0};
    char t0[64], t1[64], now[64];
    fmt_timestamp(a->g.first_ts, t0, sizeof t0);
    fmt_timestamp(a->g.last_ts, t1, sizeof t1);
    fmt_timestamp((double)time(NULL), now, sizeof now);
    cell(&cb, "Plik źródłowy");          cell(&cb, "%s", a->path);
    cell(&cb, "Typ warstwy łącza");      cell(&cb, "%s", a->datalink_name);
    cell(&cb, "Pierwszy pakiet");        cell(&cb, "%s", a->g.have_ts ? t0 : "-");
    cell(&cb, "Ostatni pakiet");         cell(&cb, "%s", a->g.have_ts ? t1 : "-");
    cell(&cb, "Data wygenerowania");     cell(&cb, "%s", now);
    cell(&cb, "Narzędzie");              cell(&cb, PA_NAME " " PA_VERSION " (C, libpcap, cairo)");
    static const double w[] = {0.28, 0.72};
    tspec_t t = {2, NULL, w, "ll"};
    doc_table(d, &t, &cb, NULL);
    cells_free(&cb);

    use_font(cr, 8.5, 1);
    set_rgb(cr, COL_INK2);
    cairo_move_to(cr, MARGIN_L, d->y + 8);
    cairo_show_text(cr, "Zawartość raportu");
    d->y += 16;
    static const char *const toc[] = {
        "1. Podsumowanie", "2. Statystyki ruchu", "3. Charakterystyka komunikacji",
        "4. Analiza protokołu TCP", "5. Analiza DNS", "6. Wykryte nieprawidłowości",
        "7. Opis prezentowanych danych", "Załącznik A. Pliki wynikowe"
    };
    use_font(cr, 8.5, 0);
    set_rgb(cr, COL_INK);
    for (size_t i = 0; i < ARRAY_LEN(toc); i++) {
        double col_x = MARGIN_L + (i < 4 ? 0 : CONTENT_W / 2);
        double row_y = d->y + (double)(i % 4) * 12.5 + 8;
        cairo_move_to(cr, col_x, row_y);
        cairo_show_text(cr, toc[i]);
    }
    d->y += 4 * 12.5 + 10;
}

static void sec_summary(doc_t *d)
{
    const analysis_t *a = d->a;
    char pk[32], vol[32], dur[32], t0[64], t1[64], tp[16], tb[16], up[16], ub[16];
    char nf[32], nt[32], nu[32], nh[32], avg[32], peak[32], pat[32];
    fmt_count(a->g.pkts, pk, sizeof pk);
    fmt_bytes((double)a->g.bytes, vol, sizeof vol);
    fmt_duration(a->duration, dur, sizeof dur);
    fmt_timestamp(a->g.first_ts, t0, sizeof t0);
    fmt_timestamp(a->g.last_ts, t1, sizeof t1);
    fmt_percent(ratio(a->g.pb_pkts[PB_TCP], a->g.pkts), tp, sizeof tp);
    fmt_percent(ratio(a->g.pb_bytes[PB_TCP], a->g.bytes), tb, sizeof tb);
    fmt_percent(ratio(a->g.pb_pkts[PB_UDP], a->g.pkts), up, sizeof up);
    fmt_percent(ratio(a->g.pb_bytes[PB_UDP], a->g.bytes), ub, sizeof ub);
    fmt_count(a->flows.n, nf, sizeof nf);
    fmt_count(a->tcp_flows, nt, sizeof nt);
    fmt_count(a->udp_flows, nu, sizeof nu);
    fmt_count(a->hosts.n, nh, sizeof nh);
    fmt_bitrate(a->duration > 0 ? (double)a->g.bytes * 8.0 / a->duration : 0, avg, sizeof avg);
    double pb, pp, pt;
    peak_rates(a, &pb, &pp, &pt);
    fmt_bitrate(pb, peak, sizeof peak);
    fmt_fixed(pt, 0, pat, sizeof pat);

    doc_heading(d, 1, "1. Podsumowanie");
    if (a->g.pkts == 0) {
        doc_para(d, "Plik nie zawiera żadnych pakietów – analiza nie mogła zostać "
                    "przeprowadzona. Pozostałe sekcje raportu zawierają wartości zerowe.");
    } else {
        doc_paraf(d,
            "Analizowany plik %s zawiera %s pakietów o łącznym wolumenie %s, zarejestrowanych "
            "w ciągu %s (od %s do %s). Ruch TCP stanowi %s pakietów i %s wolumenu, a ruch "
            "UDP – %s pakietów i %s wolumenu. Zrekonstruowano %s przepływów (%s TCP, %s UDP) "
            "pomiędzy %s adresami IP. Średnia przepływność wyniosła %s, a maksymalna "
            "w przedziale jednosekundowym – %s (ok. %s s od początku zapisu).",
            a->name, pk, vol, dur, t0, t1, tp, tb, up, ub, nf, nt, nu, nh, avg, peak, pat);
    }
    if (a->tcp_flows) {
        char med[32], p95[32], rr[16];
        fmt_duration(a->rtt_median, med, sizeof med);
        fmt_duration(a->rtt_p95, p95, sizeof p95);
        fmt_percent(ratio(a->retrans_total, a->data_segs_total), rr, sizeof rr);
        if (a->nrtt)
            doc_paraf(d,
                "Pełne uzgadnianie trójetapowe zaobserwowano w %llu połączeniach TCP; mediana "
                "czasu uzgadniania wyniosła %s, a 95. percentyl %s. Retransmitowano %s "
                "segmentów TCP zawierających dane.",
                (unsigned long long)a->tcp_established, med, p95, rr);
        else
            doc_paraf(d,
                "W zapisie nie zaobserwowano kompletnego uzgadniania trójetapowego TCP. "
                "Retransmitowano %s segmentów TCP zawierających dane.", rr);
    }
    if (a->read_warning[0])
        doc_paraf(d, "Uwaga: %s. Wyniki obejmują pakiety odczytane przed błędem.",
                  a->read_warning);

    doc_heading(d, 2, "Najważniejsze ustalenia");
    int shown = 0;
    for (size_t i = 0; i < a->nanom && shown < 10; i++) {
        if (a->anom[i].sev == SEV_INFO)
            continue;
        doc_badge_line(d, a->anom[i].sev, a->anom[i].title);
        shown++;
    }
    if (!shown)
        doc_para(d, "Nie wykryto nieprawidłowości o poziomie ważności NISKI lub wyższym. "
                    "Ruch ma charakter typowy dla prawidłowo działającej sieci; ewentualne "
                    "uwagi informacyjne przedstawiono w sekcji 6.");
    else
        doc_para(d, "Szczegółowy opis każdej nieprawidłowości, wraz z interpretacją "
                    "i przedziałem czasu, zawiera sekcja 6.");
}

static void sec_traffic(doc_t *d, const figure_set_t *fs, int png)
{
    const analysis_t *a = d->a;
    const gstats_t *g = &a->g;
    char x1[64], x2[64], x3[64];

    doc_heading(d, 1, "2. Statystyki ruchu");
    doc_para(d, "Sekcja przedstawia ilościowy opis ruchu: wolumen, natężenie, udział "
                "protokołów i rozkład rozmiarów pakietów.");
    cells_t cb = {0};
    fmt_count(g->pkts, x1, sizeof x1);
    cell(&cb, "Liczba pakietów"); cell(&cb, "%s", x1);
    fmt_bytes((double)g->bytes, x1, sizeof x1);
    cell(&cb, "Wolumen (suma długości ramek)"); cell(&cb, "%s", x1);
    fmt_bytes((double)g->tcp_payload, x1, sizeof x1);
    fmt_bytes((double)g->udp_payload, x2, sizeof x2);
    cell(&cb, "Dane aplikacyjne TCP / UDP"); cell(&cb, "%s / %s", x1, x2);
    fmt_duration(a->duration, x1, sizeof x1);
    cell(&cb, "Czas trwania zapisu"); cell(&cb, "%s", x1);
    fmt_bitrate(a->duration > 0 ? (double)g->bytes * 8 / a->duration : 0, x1, sizeof x1);
    double pb, pp, pt;
    peak_rates(a, &pb, &pp, &pt);
    fmt_bitrate(pb, x2, sizeof x2);
    cell(&cb, "Przepływność średnia / maksymalna (1 s)"); cell(&cb, "%s / %s", x1, x2);
    fmt_compact(a->duration > 0 ? (double)g->pkts / a->duration : 0, x1, sizeof x1);
    fmt_compact(pp, x2, sizeof x2);
    cell(&cb, "Natężenie średnie / maksymalne (1 s)"); cell(&cb, "%s / %s pakietów/s", x1, x2);
    fmt_fixed(g->pkts ? (double)g->bytes / (double)g->pkts : 0, 1, x1, sizeof x1);
    cell(&cb, "Długość ramki: min. / średnia / maks.");
    cell(&cb, "%u / %s / %u B", g->pkts ? g->min_len : 0, x1, g->max_len);
    fmt_count(g->ipv4, x1, sizeof x1);
    fmt_count(g->ipv6, x2, sizeof x2);
    cell(&cb, "Pakiety IPv4 / IPv6"); cell(&cb, "%s / %s", x1, x2);
    fmt_count(g->vlan, x1, sizeof x1);
    cell(&cb, "Ramki ze znacznikiem VLAN"); cell(&cb, "%s", x1);
    fmt_count(g->frags, x1, sizeof x1);
    cell(&cb, "Fragmenty IP"); cell(&cb, "%s", x1);
    fmt_count(a->hosts.n, x1, sizeof x1);
    cell(&cb, "Unikalne adresy IP"); cell(&cb, "%s", x1);
    fmt_count(g->truncated, x1, sizeof x1);
    fmt_count(g->malformed, x2, sizeof x2);
    fmt_count(g->bad_ipcksum, x3, sizeof x3);
    cell(&cb, "Nagłówki obcięte / niespójne / błędne sumy IPv4");
    cell(&cb, "%s / %s / %s", x1, x2, x3);
    doc_kv_table(d, &cb, "Statystyki ogólne");
    cells_free(&cb);

    {
        static const char *const hdr[] = {"Protokół", "Pakiety", "% pakietów", "Wolumen",
                                          "% wolumenu", "Śr. ramka"};
        static const double w[] = {0.20, 0.16, 0.15, 0.17, 0.16, 0.16};
        static const char *const names[PB_COUNT] = {"TCP", "UDP", "ICMP/ICMPv6",
                                                    "Inne IP", "Nie-IP (ARP i in.)"};
        tspec_t t = {6, hdr, w, "lrrrrr"};
        for (int i = 0; i < PB_COUNT; i++) {
            fmt_count(g->pb_pkts[i], x1, sizeof x1);
            fmt_percent(ratio(g->pb_pkts[i], g->pkts), x2, sizeof x2);
            cell(&cb, "%s", names[i]);
            cell(&cb, "%s", x1);
            cell(&cb, "%s", x2);
            fmt_bytes((double)g->pb_bytes[i], x1, sizeof x1);
            fmt_percent(ratio(g->pb_bytes[i], g->bytes), x2, sizeof x2);
            fmt_fixed(g->pb_pkts[i] ? (double)g->pb_bytes[i] / (double)g->pb_pkts[i] : 0, 0,
                      x3, sizeof x3);
            cell(&cb, "%s", x1);
            cell(&cb, "%s", x2);
            cell(&cb, "%s B", x3);
        }
        doc_table(d, &t, &cb, "Podział ruchu według protokołów");
        cells_free(&cb);
    }
    doc_figure(d, &fs->fig[FIG_THROUGHPUT], png);
    doc_figure(d, &fs->fig[FIG_PPS], png);
    doc_figure(d, &fs->fig[FIG_PROTO], png);
    doc_figure(d, &fs->fig[FIG_SIZES], png);
}

typedef struct {
    size_t   idx;
    uint64_t key;
} rk_t;

static int cmp_rk(const void *pa, const void *pb)
{
    const rk_t *x = pa, *y = pb;
    if (x->key != y->key)
        return x->key > y->key ? -1 : 1;
    return (x->idx > y->idx) - (x->idx < y->idx);
}

static void sec_communication(doc_t *d, const figure_set_t *fs, int png)
{
    const analysis_t *a = d->a;
    int topn = a->cfg.top_n;
    char x1[64], x2[64], x3[64], x4[64];
    char title[128];

    doc_heading(d, 1, "3. Charakterystyka komunikacji");
    doc_para(d, "Sekcja opisuje, kto i z kim się komunikuje: najaktywniejsze hosty, "
                "wykorzystywane usługi, największe przepływy oraz ich stan i charakter.");

    /* najaktywniejsze hosty */
    size_t nh = a->hosts.n;
    rk_t *rk = xmalloc((nh ? nh : 1) * sizeof *rk);
    for (size_t i = 0; i < nh; i++) {
        rk[i].idx = i;
        rk[i].key = a->hosts.items[i].bytes_in + a->hosts.items[i].bytes_out;
    }
    qsort(rk, nh, sizeof *rk, cmp_rk);
    {
        static const char *const hdr[] = {"Adres IP", "Wysłane", "Odebrane", "Pakiety wys./odebr.",
                                          "Przepływy inic./obsł."};
        static const double w[] = {0.30, 0.15, 0.15, 0.20, 0.20};
        tspec_t t = {5, hdr, w, "lrrrr"};
        cells_t cb = {0};
        for (size_t i = 0; i < nh && i < (size_t)topn; i++) {
            const host_t *h = &a->hosts.items[rk[i].idx];
            char ip[IPSTR_LEN];
            fmt_bytes((double)h->bytes_out, x1, sizeof x1);
            fmt_bytes((double)h->bytes_in, x2, sizeof x2);
            fmt_count(h->pkts_out, x3, sizeof x3);
            fmt_count(h->pkts_in, x4, sizeof x4);
            cell(&cb, "%s", ip_str(&h->ip, ip, sizeof ip));
            cell(&cb, "%s", x1);
            cell(&cb, "%s", x2);
            cell(&cb, "%s / %s", x3, x4);
            cell(&cb, "%u / %u", h->flows_init, h->flows_resp);
        }
        snprintf(title, sizeof title, "Najaktywniejsze hosty (top %d wg wolumenu)", topn);
        doc_table(d, &t, &cb, title);
        cells_free(&cb);
    }
    free(rk);
    doc_figure(d, &fs->fig[FIG_TALKERS], png);
    doc_figure(d, &fs->fig[FIG_SERVICES], png);

    /* największe przepływy */
    size_t nf = a->flows.n;
    rk_t *fr = xmalloc((nf ? nf : 1) * sizeof *fr);
    for (size_t i = 0; i < nf; i++) {
        fr[i].idx = i;
        fr[i].key = a->flows.list[i]->bytes[0] + a->flows.list[i]->bytes[1];
    }
    qsort(fr, nf, sizeof *fr, cmp_rk);
    {
        static const char *const hdr[] = {"Klient → serwer", "Usługa", "Czas", "Pakiety",
                                          "Wolumen", "Stan"};
        static const double w[] = {0.33, 0.15, 0.10, 0.10, 0.11, 0.21};
        tspec_t t = {6, hdr, w, "llrrrl"};
        cells_t cb = {0};
        for (size_t i = 0; i < nf && i < (size_t)topn; i++) {
            const flow_t *f = a->flows.list[fr[i].idx];
            char c[IPSTR_LEN], s[IPSTR_LEN], svc[64];
            ip_str(flow_cli(f), c, sizeof c);
            ip_str(flow_srv(f), s, sizeof s);
            fmt_service(f->key.proto, flow_sport(f), svc, sizeof svc);
            fmt_duration(f->last_ts - f->first_ts, x1, sizeof x1);
            fmt_count(f->pkts[0] + f->pkts[1], x2, sizeof x2);
            fmt_bytes((double)(f->bytes[0] + f->bytes[1]), x3, sizeof x3);
            cell(&cb, "%s:%u → %s", c, (unsigned)flow_cport(f), s);
            cell(&cb, "%s", svc);
            cell(&cb, "%s", x1);
            cell(&cb, "%s", x2);
            cell(&cb, "%s", x3);
            cell(&cb, "%s", flow_class_name(flow_classify(f)));
        }
        snprintf(title, sizeof title, "Największe przepływy (top %d wg wolumenu)", topn);
        doc_table(d, &t, &cb, title);
        cells_free(&cb);
    }
    free(fr);
    doc_figure(d, &fs->fig[FIG_FLOWSTATES], png);
    doc_figure(d, &fs->fig[FIG_SCATTER], png);
}

static void sec_tcp(doc_t *d, const figure_set_t *fs, int png)
{
    const analysis_t *a = d->a;
    char x1[64], x2[64], x3[64], x4[64];

    doc_heading(d, 1, "4. Analiza protokołu TCP");
    doc_para(d, "Sekcja przedstawia przebieg nawiązywania i zamykania połączeń TCP, "
                "czasy uzgadniania oraz wskaźniki jakości transmisji.");
    cells_t cb = {0};
    cell(&cb, "Przepływy TCP"); cell(&cb, "%llu", (unsigned long long)a->tcp_flows);
    cell(&cb, "Połączenia nawiązane (pełne uzgadnianie)");
    cell(&cb, "%llu", (unsigned long long)a->tcp_established);
    for (int c = FC_COMPLETE; c <= FC_MIDSTREAM; c++) {
        cell(&cb, "– %s", flow_class_name((flow_class_t)c));
        cell(&cb, "%llu", (unsigned long long)a->fc_count[c]);
    }
    if (a->nrtt) {
        fmt_duration(a->rtt_median, x1, sizeof x1);
        fmt_duration(a->rtt_mean, x2, sizeof x2);
        fmt_duration(a->rtt_p95, x3, sizeof x3);
        fmt_duration(a->rtt_max, x4, sizeof x4);
        cell(&cb, "Czas uzgadniania: mediana / średnia / p95 / maks.");
        cell(&cb, "%s / %s / %s / %s", x1, x2, x3, x4);
    } else {
        cell(&cb, "Czas uzgadniania"); cell(&cb, "brak kompletnych uzgodnień");
    }
    fmt_count(a->data_segs_total, x1, sizeof x1);
    cell(&cb, "Segmenty z danymi"); cell(&cb, "%s", x1);
    fmt_percent(ratio(a->retrans_total, a->data_segs_total), x2, sizeof x2);
    cell(&cb, "Retransmisje"); cell(&cb, "%llu (%s)", (unsigned long long)a->retrans_total, x2);
    cell(&cb, "Segmenty poza kolejnością"); cell(&cb, "%llu", (unsigned long long)a->ooo_total);
    cell(&cb, "Luki w numeracji (segmenty niezarejestrowane)");
    cell(&cb, "%llu", (unsigned long long)a->gaps_total);
    cell(&cb, "Zduplikowane ACK"); cell(&cb, "%llu", (unsigned long long)a->dupack_total);
    cell(&cb, "Segmenty z zerowym oknem"); cell(&cb, "%llu", (unsigned long long)a->zerowin_total);
    cell(&cb, "Segmenty keep-alive"); cell(&cb, "%llu", (unsigned long long)a->keepalive_total);
    cell(&cb, "Retransmisje SYN"); cell(&cb, "%llu", (unsigned long long)a->syn_retx_total);
    cell(&cb, "Segmenty SYN / SYN-ACK / FIN / RST");
    cell(&cb, "%llu / %llu / %llu / %llu", (unsigned long long)a->g.syn_only,
         (unsigned long long)a->g.synack, (unsigned long long)a->g.fin_pkts,
         (unsigned long long)a->g.rst_pkts);
    doc_kv_table(d, &cb, "Wskaźniki połączeń TCP");
    cells_free(&cb);

    doc_figure(d, &fs->fig[FIG_FLAGS], png);
    doc_figure(d, &fs->fig[FIG_HANDSHAKE], png);
    doc_figure(d, &fs->fig[FIG_RTT], png);
    doc_figure(d, &fs->fig[FIG_TCPHEALTH], png);
}

static void sec_dns(doc_t *d)
{
    const dns_stats_t *s = &d->a->dns;
    doc_heading(d, 1, "5. Analiza DNS");
    if (s->queries + s->responses == 0) {
        doc_para(d, "W zapisie nie wystąpił ruch DNS przesyłany protokołem UDP na porcie 53.");
        return;
    }
    doc_para(d, "Statystyki komunikatów DNS przesyłanych protokołem UDP na porcie 53 "
                "(zapytania DNS over TLS/HTTPS są szyfrowane i nie podlegają tej analizie).");
    cells_t cb = {0};
    char x1[32];
    cell(&cb, "Zapytania / odpowiedzi");
    cell(&cb, "%llu / %llu", (unsigned long long)s->queries, (unsigned long long)s->responses);
    fmt_percent(ratio(s->nxdomain, s->responses), x1, sizeof x1);
    cell(&cb, "Odpowiedzi NXDOMAIN"); cell(&cb, "%llu (%s)", (unsigned long long)s->nxdomain, x1);
    cell(&cb, "Odpowiedzi SERVFAIL"); cell(&cb, "%llu", (unsigned long long)s->servfail);
    cell(&cb, "Typy zapytań: A / AAAA / TXT / MX / ANY / inne");
    cell(&cb, "%llu / %llu / %llu / %llu / %llu / %llu", (unsigned long long)s->qt_a,
         (unsigned long long)s->qt_aaaa, (unsigned long long)s->qt_txt,
         (unsigned long long)s->qt_mx, (unsigned long long)s->qt_any,
         (unsigned long long)s->qt_other);
    fmt_fixed(s->queries ? s->qname_sum / (double)s->queries : 0, 1, x1, sizeof x1);
    cell(&cb, "Długość nazwy: średnia / maksymalna"); cell(&cb, "%s / %u znaków", x1, s->max_qname);
    cell(&cb, "Najdłuższa nazwa"); cell(&cb, "%s", s->longest[0] ? s->longest : "-");
    cell(&cb, "Zapytania podejrzane (heurystyka tunelowania)");
    cell(&cb, "%llu (hosty: %zu)", (unsigned long long)s->suspicious, s->nsusp);
    cell(&cb, "Komunikaty niepoprawne"); cell(&cb, "%llu", (unsigned long long)s->malformed);
    doc_kv_table(d, &cb, "Statystyki DNS");
    cells_free(&cb);
}

static void sec_anomalies(doc_t *d)
{
    const analysis_t *a = d->a;
    cairo_t *cr = d->cr;
    doc_heading(d, 1, "6. Wykryte nieprawidłowości");
    {
        static const char *const hdr[] = {"Poziom", "Liczba", "Znaczenie"};
        static const double w[] = {0.16, 0.12, 0.72};
        static const char *const mean[SEV_COUNT] = {
            "Obserwacja informacyjna, bez negatywnej oceny.",
            "Drobna nieprawidłowość lub objaw problemów wydajnościowych.",
            "Zjawisko nietypowe, wymagające analizy.",
            "Zjawisko o wysokim prawdopodobieństwie złośliwego charakteru."
        };
        tspec_t t = {3, hdr, w, "lrl"};
        cells_t cb = {0};
        for (int s = SEV_HIGH; s >= SEV_INFO; s--) {
            cell(&cb, "%s", severity_name((severity_t)s));
            cell(&cb, "%d", analysis_count_severity(a, (severity_t)s));
            cell(&cb, "%s", mean[s]);
        }
        doc_table(d, &t, &cb, "Liczba nieprawidłowości według poziomu ważności");
        cells_free(&cb);
    }
    if (a->nanom == 0) {
        doc_para(d, "Żaden z detektorów nie zgłosił nieprawidłowości przy zastosowanych "
                    "progach.");
        return;
    }
    for (size_t i = 0; i < a->nanom; i++) {
        const anomaly_t *x = &a->anom[i];
        char title[300], meta[200];
        snprintf(title, sizeof title, "%zu. %s", i + 1, x->title);
        if (x->t_start >= 0) {
            char t0[32], t1[32];
            fmt_fixed(x->t_start, 1, t0, sizeof t0);
            fmt_fixed(x->t_end, 1, t1, sizeof t1);
            snprintf(meta, sizeof meta, "Kategoria: %s · Czas: %s–%s s od początku zapisu",
                     x->category, t0, t1);
        } else {
            snprintf(meta, sizeof meta, "Kategoria: %s · Dotyczy całego zapisu", x->category);
        }
        doc_need(d, 70);
        double bw = draw_badge(cr, MARGIN_L, d->y + 1, severity_name(x->sev),
                               sev_color(x->sev));
        (void)bw;
        d->y += 16;
        doc_text(d, title, 10, 1, COL_INK, 0, 13.5);
        doc_text(d, meta, 7.8, 0, COL_MUTED, 0, 11);
        d->y += 2;
        doc_text(d, x->detail, FS_BODY, 0, COL_INK, 0, LH_BODY);
        d->y += 6;
        set_rgb(cr, COL_GRID);
        cairo_set_line_width(cr, 0.6);
        cairo_move_to(cr, MARGIN_L, d->y);
        cairo_line_to(cr, PAGE_W - MARGIN_R, d->y);
        cairo_stroke(cr);
        d->y += 10;
    }
}

static void sec_data_desc(doc_t *d)
{
    doc_heading(d, 1, "7. Opis prezentowanych danych");
    doc_para(d, "Definicje miar i pojęć używanych w raporcie:");
    doc_bullet(d, "Pakiet / ramka – pojedynczy rekord pliku pcap. Wolumen to suma oryginalnych "
                  "długości ramek (z nagłówkiem warstwy łącza, bez sumy kontrolnej FCS); "
                  "jednostki dziesiętne (1 kB = 1000 B, 1 Mb/s = 10^6 b/s).");
    doc_bullet(d, "Dane aplikacyjne – liczba bajtów ładunku TCP/UDP wyznaczona z nagłówków IP "
                  "i warstwy transportowej.");
    doc_bullet(d, "Przepływ – dwukierunkowy strumień pakietów o tej samej piątce (protokół, "
                  "adresy, porty). Klient (inicjator) to strona rozpoczynająca komunikację, "
                  "serwer – strona odpowiadająca; usługa to protokół i port serwera.");
    doc_bullet(d, "Przepływność / natężenie – liczba bitów / pakietów w przedziale czasu "
                  "podzielona przez jego szerokość. Wartości maksymalne liczone są "
                  "w przedziałach 1 s.");
    doc_bullet(d, "Czas uzgadniania – odstęp między segmentem SYN a końcowym ACK klienta. "
                  "Percentyl p95 – wartość, poniżej której leży 95% pomiarów.");
    doc_bullet(d, "Retransmisja – ponowne wysłanie danych o już zaobserwowanych numerach "
                  "sekwencyjnych. Luka – brak w zapisie segmentu o oczekiwanym numerze. "
                  "Dup ACK – powtórzone potwierdzenie sygnalizujące nadawcy brak segmentu. "
                  "Zerowe okno – odbiorca wstrzymuje nadawcę z powodu pełnego bufora.");
    doc_bullet(d, "Mediana i MAD – odporne miary położenia i rozproszenia: mediana to wartość "
                  "środkowa, a MAD – mediana odchyleń bezwzględnych od mediany; współczynnik "
                  "1,4826 skaluje MAD do odchylenia standardowego rozkładu normalnego.");
    doc_bullet(d, "Współczynnik zmienności (CV) – odchylenie standardowe odstępów między "
                  "połączeniami podzielone przez ich średnią; wartości bliskie zera oznaczają "
                  "komunikację ściśle okresową.");
    doc_bullet(d, "Czasy w sekcji 6 podawane są w sekundach względem pierwszego pakietu "
                  "w pliku; znaczniki bezwzględne – w strefie UTC.");

    doc_heading(d, 2, "Ograniczenia analizy");
    doc_bullet(d, "Analiza obejmuje nagłówki protokołów; treść szyfrowana (TLS, QUIC, DoH) "
                  "nie jest interpretowana, a usługi rozpoznawane są po numerach portów.");
    doc_bullet(d, "Wyniki analizy TCP zależą od położenia punktu przechwytywania: utracone "
                  "przed nim segmenty widoczne są jako luki, a po nim – jako retransmisje.");
    doc_bullet(d, "Wartości progowe detektorów są heurystyczne; zgłoszenie oznacza zjawisko "
                  "wymagające weryfikacji, a nie przesądza o incydencie bezpieczeństwa. "
                  "Przy zapisach krótszych niż kilkanaście sekund detekcja skoków natężenia "
                  "i okresowości jest pomijana lub mniej wiarygodna.");
    doc_bullet(d, "Fragmenty IP nie są składane; kolejne fragmenty uwzględniane są wyłącznie "
                  "w statystykach wolumenu.");
}

static void sec_files(doc_t *d, const figure_set_t *fs, int png)
{
    doc_heading(d, 1, "Załącznik A. Pliki wynikowe");
    doc_para(d, "W katalogu wynikowym analizy zapisano następujące pliki:");
    static const char *const hdr[] = {"Plik", "Zawartość"};
    static const double w[] = {0.38, 0.62};
    tspec_t t = {2, hdr, w, "ll"};
    cells_t cb = {0};
    cell(&cb, "raport.pdf"); cell(&cb, "Niniejszy raport.");
    cell(&cb, "przeplywy.csv");
    cell(&cb, "Lista wszystkich przepływów: punkty końcowe, czasy, liczniki pakietów i bajtów "
              "w obu kierunkach, stan, czas uzgadniania, wskaźniki jakości TCP.");
    cell(&cb, "podsumowanie.txt"); cell(&cb, "Podsumowanie tekstowe z listą nieprawidłowości.");
    if (png)
        for (int i = 0; i < FIG_COUNT; i++) {
            cell(&cb, "%s", fs->fig[i].file);
            cell(&cb, "%s (PNG 1600×900).", fs->fig[i].caption);
        }
    doc_table(d, &t, &cb, "Pliki wynikowe");
    cells_free(&cb);
}

/* ======================= API ======================= */

static int doc_open(doc_t *d, const char *path, const char *title, const char *subject)
{
    d->surf = cairo_pdf_surface_create(path, PAGE_W, PAGE_H);
    if (cairo_surface_status(d->surf) != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(d->surf);
        d->surf = NULL;
        return -1;
    }
#ifdef HAVE_PDF_OUTLINE
    cairo_pdf_surface_set_metadata(d->surf, CAIRO_PDF_METADATA_TITLE, title);
    cairo_pdf_surface_set_metadata(d->surf, CAIRO_PDF_METADATA_CREATOR, PA_NAME " " PA_VERSION);
    cairo_pdf_surface_set_metadata(d->surf, CAIRO_PDF_METADATA_SUBJECT, subject);
#else
    (void)title;
    (void)subject;
#endif
    d->cr = cairo_create(d->surf);
    doc_page_begin(d);
    return 0;
}

static int doc_close(doc_t *d)
{
    doc_footer(d);
    cairo_show_page(d->cr);
    cairo_status_t st = cairo_status(d->cr);
    cairo_destroy(d->cr);
    cairo_surface_finish(d->surf);
    if (st == CAIRO_STATUS_SUCCESS)
        st = cairo_surface_status(d->surf);
    cairo_surface_destroy(d->surf);
    return st == CAIRO_STATUS_SUCCESS ? 0 : -1;
}

int report_write_pdf(const analysis_t *a, const figure_set_t *fs, const char *path,
                     int png_written)
{
    doc_t d;
    char title[400];
    memset(&d, 0, sizeof d);
    d.a = a;
    d.footer = PA_NAME " " PA_VERSION " · raport wygenerowany automatycznie";
    snprintf(d.header, sizeof d.header, "Raport analizy ruchu TCP/UDP · %s", a->name);
    snprintf(title, sizeof title, "Raport analizy ruchu TCP/UDP – %s", a->name);
    if (doc_open(&d, path, title, "Analiza komunikacji TCP i UDP z pliku pcap") != 0)
        return -1;

    sec_title(&d);
    sec_summary(&d);
    sec_traffic(&d, fs, png_written);
    sec_communication(&d, fs, png_written);
    sec_tcp(&d, fs, png_written);
    sec_dns(&d);
    sec_anomalies(&d);
    sec_data_desc(&d);
    sec_files(&d, fs, png_written);
    return doc_close(&d);
}
