/*
 * charts.h - silnik wykresów oparty na bibliotece cairo.
 *
 * Wykres jest opisany deklaratywnie strukturą chart_t i rysowany funkcją
 * chart_render() na dowolnej powierzchni cairo: tę samą definicję zapisuje
 * się do pliku PNG (powierzchnia rastrowa) i osadza wektorowo w raporcie PDF.
 */
#ifndef PA_CHARTS_H
#define PA_CHARTS_H

#include <cairo.h>
#include <stddef.h>
#include <stdint.h>

#define FONT_SANS "DejaVu Sans"
#define FONT_MONO "DejaVu Sans Mono"

/* Logiczny rozmiar wykresu (jednostki cairo). PNG jest skalowany x2. */
#define CHART_W 800.0
#define CHART_H 450.0

/* Paleta (tryb jasny): powierzchnia, tusz, siatka, osie. */
#define COL_SURFACE  0xfcfcfb
#define COL_INK      0x0b0b0b
#define COL_INK2     0x52514e
#define COL_MUTED    0x898781
#define COL_GRID     0xe1e0d9
#define COL_AXIS     0xc3c2b7
#define COL_PANEL    0xf0efec

/* Kolory statusu (ważność nieprawidłowości). */
#define COL_GOOD     0x0ca30c
#define COL_WARNING  0xfab219
#define COL_SERIOUS  0xec835a
#define COL_CRITICAL 0xd03b3b

/* Kategoryczna paleta serii (stała kolejność). */
extern const uint32_t CHART_PALETTE[8];
#define COL_TCP   0x2a78d6
#define COL_UDP   0xeb6834
#define COL_OTHER 0x1baf7a

typedef enum { CH_LINE = 0, CH_BAR, CH_HBAR, CH_SCATTER } chart_type_t;
typedef enum { VF_NUM = 0, VF_BYTES, VF_BITRATE, VF_PERCENT, VF_SECONDS, VF_MS } value_fmt_t;

#define CHART_MAX_SERIES 6

typedef struct {
    const char   *name;
    const double *x;      /* CH_LINE/CH_SCATTER; NULL = indeksy        */
    const double *y;      /* CH_BAR/CH_HBAR: ncat wartości             */
    int           n;
    uint32_t      color;
} chart_series_t;

typedef struct {
    chart_type_t type;
    const char  *title;
    const char  *subtitle;
    const char  *xlabel;
    const char  *ylabel;
    value_fmt_t  xfmt, yfmt;
    int          log_x, log_y;
    int          stacked;        /* CH_BAR/CH_HBAR: słupki skumulowane  */
    int          value_labels;   /* CH_HBAR: wartości przy słupkach     */
    const char *const *categories;
    int          ncat;
    chart_series_t series[CHART_MAX_SERIES];
    int          nseries;
} chart_t;

void   chart_render(cairo_t *cr, const chart_t *c, double w, double h);
int    chart_write_png(const chart_t *c, const char *path, double scale);

/* Narzędzia wykorzystywane również przez generator raportu. */
void   set_rgb(cairo_t *cr, uint32_t rgb);
void   set_rgba(cairo_t *cr, uint32_t rgb, double alpha);
void   use_font(cairo_t *cr, double size, int bold);
double text_width(cairo_t *cr, const char *s);
void   fit_text(cairo_t *cr, const char *s, double maxw, char *out, size_t n);
void   fmt_value(double v, value_fmt_t f, char *buf, size_t n);

#endif
