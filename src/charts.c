/*
 * charts.c - rysowanie wykresów liniowych, słupkowych (pionowych
 * i poziomych) oraz punktowych za pomocą cairo.
 *
 * Zasady: jedna oś wartości (bez osi podwójnych), stonowana siatka,
 * cienkie linie (2 px), zaokrąglone końce słupków, odstęp 2 px pomiędzy
 * segmentami, legenda dla >= 2 serii oraz bezpośrednie etykiety serii na
 * wykresach liniowych. Tekst zawsze w kolorach tuszu, nie w kolorach serii.
 */
#include "charts.h"
#include "common.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

const uint32_t CHART_PALETTE[8] = {
    0x2a78d6, 0xeb6834, 0x1baf7a, 0xeda100, 0xe87ba4, 0x008300, 0x6250d6, 0xe34948
};

#define PAD 24.0

typedef struct { double x0, y0, x1, y1; } rect_t;
typedef struct { double lo, hi, step; int log; } axis_t;

/* ======================= narzędzia ======================= */

void set_rgba(cairo_t *cr, uint32_t c, double a)
{
    cairo_set_source_rgba(cr, ((c >> 16) & 0xFF) / 255.0, ((c >> 8) & 0xFF) / 255.0,
                          (c & 0xFF) / 255.0, a);
}

void set_rgb(cairo_t *cr, uint32_t c)
{
    set_rgba(cr, c, 1.0);
}

void use_font(cairo_t *cr, double size, int bold)
{
    cairo_select_font_face(cr, FONT_SANS, CAIRO_FONT_SLANT_NORMAL,
                           bold ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, size);
}

double text_width(cairo_t *cr, const char *s)
{
    cairo_text_extents_t e;
    cairo_text_extents(cr, s, &e);
    return e.x_advance;
}

void fit_text(cairo_t *cr, const char *s, double maxw, char *out, size_t n)
{
    if (n == 0)
        return;
    snprintf(out, n, "%s", s);
    if (text_width(cr, out) <= maxw)
        return;
    size_t len = strlen(out);
    while (len > 0) {
        len--;
        while (len > 0 && ((unsigned char)s[len] & 0xC0) == 0x80)
            len--;
        if (len + 4 > n)
            continue;
        memcpy(out, s, len);
        memcpy(out + len, "\xE2\x80\xA6", 4);    /* "…" i znak końca */
        if (text_width(cr, out) <= maxw)
            return;
    }
    snprintf(out, n, "%s", n >= 4 ? "\xE2\x80\xA6" : "");
}

void fmt_value(double v, value_fmt_t f, char *buf, size_t n)
{
    char t[48];
    switch (f) {
    case VF_BYTES:
        fmt_bytes(v, buf, n);
        break;
    case VF_BITRATE:
        fmt_bitrate(v, buf, n);
        break;
    case VF_PERCENT:
        fmt_compact(v * 100.0, t, sizeof t);
        snprintf(buf, n, "%s%%", t);
        break;
    case VF_SECONDS:
        if (v == 0)
            snprintf(buf, n, "0 s");
        else if (fabs(v) < 1e-3)
            snprintf(buf, n, "%g µs", v * 1e6);
        else if (fabs(v) < 1.0)
            snprintf(buf, n, "%g ms", v * 1e3);
        else
            snprintf(buf, n, "%g s", v);
        for (char *p = buf; *p; p++)    /* przecinek dziesiętny */
            if (*p == '.')
                *p = ',';
        (void)t;
        break;
    case VF_MS:
        fmt_compact(v, t, sizeof t);
        snprintf(buf, n, "%s ms", t);
        break;
    default:
        fmt_compact(v, buf, n);
        break;
    }
}

static void text_at(cairo_t *cr, double x, double y, const char *s, int align)
{
    double w = text_width(cr, s);
    if (align == 1)
        x -= w / 2;
    else if (align == 2)
        x -= w;
    cairo_move_to(cr, x, y);
    cairo_show_text(cr, s);
}

static void rounded_rect(cairo_t *cr, double x, double y, double w, double h, double r)
{
    if (r > w / 2) r = w / 2;
    if (r > h / 2) r = h / 2;
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r, r, -M_PI / 2, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0, M_PI / 2);
    cairo_arc(cr, x + r, y + h - r, r, M_PI / 2, M_PI);
    cairo_arc(cr, x + r, y + r, r, M_PI, 1.5 * M_PI);
    cairo_close_path(cr);
}

/* Słupek pionowy z zaokrąglonym górnym końcem (koniec danych). */
static void path_bar_v(cairo_t *cr, double x, double y, double w, double h, double r)
{
    cairo_new_path(cr);
    if (r > w / 2) r = w / 2;
    if (r > h) r = h;
    if (r < 0.5) {
        cairo_rectangle(cr, x, y, w, h);
        return;
    }
    cairo_move_to(cr, x, y + h);
    cairo_line_to(cr, x, y + r);
    cairo_arc(cr, x + r, y + r, r, M_PI, 1.5 * M_PI);
    cairo_line_to(cr, x + w - r, y);
    cairo_arc(cr, x + w - r, y + r, r, 1.5 * M_PI, 2 * M_PI);
    cairo_line_to(cr, x + w, y + h);
    cairo_close_path(cr);
}

/* Słupek poziomy z zaokrąglonym prawym końcem. */
static void path_bar_h(cairo_t *cr, double x, double y, double w, double h, double r)
{
    cairo_new_path(cr);
    if (r > h / 2) r = h / 2;
    if (r > w) r = w;
    if (r < 0.5) {
        cairo_rectangle(cr, x, y, w, h);
        return;
    }
    cairo_move_to(cr, x, y);
    cairo_line_to(cr, x + w - r, y);
    cairo_arc(cr, x + w - r, y + r, r, -M_PI / 2, 0);
    cairo_line_to(cr, x + w, y + h - r);
    cairo_arc(cr, x + w - r, y + h - r, r, 0, M_PI / 2);
    cairo_line_to(cr, x, y + h);
    cairo_close_path(cr);
}

/* ======================= osie ======================= */

static double nice_num(double x, int round_it)
{
    if (x <= 0)
        return 1.0;
    double e = floor(log10(x));
    double f = x / pow(10.0, e), nf;
    if (round_it)
        nf = f < 1.5 ? 1 : f < 3 ? 2 : f < 7 ? 5 : 10;
    else
        nf = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
    return nf * pow(10.0, e);
}

static void axis_linear(axis_t *ax, double lo, double hi, int nticks)
{
    if (!(hi > lo))
        hi = lo + 1.0;
    double range = nice_num(hi - lo, 0);
    double step = nice_num(range / (nticks - 1), 1);
    ax->lo = floor(lo / step) * step;
    ax->hi = ceil(hi / step) * step;
    if (ax->hi <= ax->lo)
        ax->hi = ax->lo + step;
    ax->step = step;
    ax->log = 0;
}

static void axis_logscale(axis_t *ax, double lo, double hi)
{
    if (lo <= 0)
        lo = 1e-6;
    if (hi <= lo)
        hi = lo * 10.0;
    ax->lo = floor(log10(lo));
    ax->hi = ceil(log10(hi));
    if (ax->hi <= ax->lo)
        ax->hi = ax->lo + 1;
    ax->step = (ax->hi - ax->lo) > 8 ? 2 : 1;
    ax->log = 1;
}

static double axis_pos(const axis_t *ax, double v)
{
    if (ax->log) {
        if (v <= 0)
            return 0;
        return (log10(v) - ax->lo) / (ax->hi - ax->lo);
    }
    return (v - ax->lo) / (ax->hi - ax->lo);
}

static int axis_ticks(const axis_t *ax, double *vals, int max)
{
    int n = 0;
    if (ax->log) {
        for (double e = ax->lo; e <= ax->hi + 1e-9 && n < max; e += ax->step)
            vals[n++] = pow(10.0, e);
    } else {
        int k = (int)floor((ax->hi - ax->lo) / ax->step + 0.5);
        for (int i = 0; i <= k && n < max; i++) {
            double v = ax->lo + i * ax->step;
            if (fabs(v) < ax->step * 1e-9)
                v = 0;
            vals[n++] = v;
        }
    }
    return n;
}

static double map_x(const rect_t *r, const axis_t *ax, double v)
{
    return r->x0 + axis_pos(ax, v) * (r->x1 - r->x0);
}

static double map_y(const rect_t *r, const axis_t *ay, double v)
{
    return r->y1 - axis_pos(ay, v) * (r->y1 - r->y0);
}

static double tick_label_width(cairo_t *cr, const axis_t *ax, value_fmt_t f)
{
    double ticks[32], w = 0;
    char buf[64];
    int nt = axis_ticks(ax, ticks, 32);
    use_font(cr, 10.5, 0);
    for (int i = 0; i < nt; i++) {
        fmt_value(ticks[i], f, buf, sizeof buf);
        double tw = text_width(cr, buf);
        if (tw > w)
            w = tw;
    }
    return w;
}

/* Poziome linie siatki i etykiety osi wartości. */
static void draw_y_grid(cairo_t *cr, const rect_t *r, const axis_t *ay, value_fmt_t f)
{
    double ticks[32];
    char buf[64];
    int nt = axis_ticks(ay, ticks, 32);
    use_font(cr, 10.5, 0);
    cairo_set_line_width(cr, 1.0);
    for (int i = 0; i < nt; i++) {
        double y = floor(map_y(r, ay, ticks[i])) + 0.5;
        set_rgb(cr, i == 0 ? COL_AXIS : COL_GRID);
        cairo_move_to(cr, r->x0, y);
        cairo_line_to(cr, r->x1, y);
        cairo_stroke(cr);
        set_rgb(cr, COL_MUTED);
        fmt_value(ticks[i], f, buf, sizeof buf);
        text_at(cr, r->x0 - 8, y + 3.5, buf, 2);
    }
}

/* Etykiety osi poziomej (z pomijaniem nakładających się). */
static void draw_x_ticks(cairo_t *cr, const rect_t *r, const axis_t *ax, value_fmt_t f,
                         int vgrid)
{
    double ticks[32], last_right = -1e9;
    char buf[64];
    int nt = axis_ticks(ax, ticks, 32);
    use_font(cr, 10.5, 0);
    cairo_set_line_width(cr, 1.0);
    for (int i = 0; i < nt; i++) {
        double x = floor(map_x(r, ax, ticks[i])) + 0.5;
        if (x < r->x0 - 1 || x > r->x1 + 1)
            continue;
        if (vgrid && i > 0) {
            set_rgb(cr, COL_GRID);
            cairo_move_to(cr, x, r->y0);
            cairo_line_to(cr, x, r->y1);
            cairo_stroke(cr);
        }
        set_rgb(cr, COL_AXIS);
        cairo_move_to(cr, x, r->y1);
        cairo_line_to(cr, x, r->y1 + 4);
        cairo_stroke(cr);
        fmt_value(ticks[i], f, buf, sizeof buf);
        double tw = text_width(cr, buf);
        if (x - tw / 2 < last_right + 6)
            continue;
        set_rgb(cr, COL_MUTED);
        text_at(cr, x, r->y1 + 17, buf, 1);
        last_right = x + tw / 2;
    }
}

static void draw_axis_titles(cairo_t *cr, const chart_t *c, const rect_t *r, double h)
{
    use_font(cr, 11, 0);
    set_rgb(cr, COL_INK2);
    if (c->xlabel)
        text_at(cr, (r->x0 + r->x1) / 2, h - 12, c->xlabel, 1);
    if (c->ylabel) {
        cairo_save(cr);
        cairo_translate(cr, PAD + 4, (r->y0 + r->y1) / 2);
        cairo_rotate(cr, -M_PI / 2);
        text_at(cr, 0, 0, c->ylabel, 1);
        cairo_restore(cr);
    }
}

static void draw_empty(cairo_t *cr, double w, double h, double top)
{
    use_font(cr, 13, 0);
    set_rgb(cr, COL_MUTED);
    text_at(cr, w / 2, (top + h) / 2, "Brak danych do przedstawienia", 1);
}

/* Nagłówek: tytuł, podtytuł i legenda. Zwraca górną krawędź obszaru danych. */
static double draw_header(cairo_t *cr, const chart_t *c, double w)
{
    char buf[256];
    double y = 32;
    use_font(cr, 16, 1);
    set_rgb(cr, COL_INK);
    fit_text(cr, c->title ? c->title : "", w - 2 * PAD, buf, sizeof buf);
    text_at(cr, PAD, y, buf, 0);
    if (c->subtitle) {
        y += 19;
        use_font(cr, 11.5, 0);
        set_rgb(cr, COL_INK2);
        fit_text(cr, c->subtitle, w - 2 * PAD, buf, sizeof buf);
        text_at(cr, PAD, y, buf, 0);
    }
    if (c->nseries >= 2) {
        y += 24;
        double x = PAD;
        use_font(cr, 11, 0);
        for (int i = 0; i < c->nseries; i++) {
            const char *nm = c->series[i].name ? c->series[i].name : "";
            double tw = text_width(cr, nm);
            if (x + 16 + tw > w - PAD && x > PAD) {
                x = PAD;
                y += 18;
            }
            set_rgb(cr, c->series[i].color);
            rounded_rect(cr, x, y - 9.5, 11, 11, 2.5);
            cairo_fill(cr);
            set_rgb(cr, COL_INK2);
            text_at(cr, x + 16, y, nm, 0);
            x += 16 + tw + 22;
        }
    }
    return y + 20;
}

/* ======================= wykres liniowy ======================= */

static void render_line(cairo_t *cr, const chart_t *c, double w, double h, double top)
{
    double xmin = INFINITY, xmax = -INFINITY, ymax = 0;
    int any = 0;
    for (int s = 0; s < c->nseries; s++) {
        const chart_series_t *se = &c->series[s];
        for (int i = 0; i < se->n; i++) {
            double x = se->x ? se->x[i] : i, y = se->y[i];
            if (!isfinite(x) || !isfinite(y))
                continue;
            any = 1;
            if (x < xmin) xmin = x;
            if (x > xmax) xmax = x;
            if (y > ymax) ymax = y;
        }
    }
    if (!any) {
        draw_empty(cr, w, h, top);
        return;
    }
    if (xmax <= xmin)
        xmax = xmin + 1;

    axis_t ax, ay;
    axis_linear(&ay, 0, ymax > 0 ? ymax : 1, 6);
    axis_linear(&ax, xmin, xmax, 8);

    double lw = tick_label_width(cr, &ay, c->yfmt);
    int direct = c->nseries >= 2 && c->nseries <= 4;
    double right = PAD;
    if (direct) {
        use_font(cr, 10.5, 0);
        double m = 0;
        for (int s = 0; s < c->nseries; s++)
            m = PA_MAX(m, text_width(cr, c->series[s].name ? c->series[s].name : ""));
        right += m + 20;
    }
    rect_t r = { PAD + (c->ylabel ? 20 : 0) + lw + 8, top + 6, w - right,
                 h - (c->xlabel ? 52 : 36) };

    draw_y_grid(cr, &r, &ay, c->yfmt);
    draw_x_ticks(cr, &r, &ax, c->xfmt, 0);
    draw_axis_titles(cr, c, &r, h);

    double lab_y[CHART_MAX_SERIES];
    int lab_ok[CHART_MAX_SERIES] = {0};

    cairo_save(cr);
    cairo_rectangle(cr, r.x0, r.y0 - 3, r.x1 - r.x0, r.y1 - r.y0 + 6);
    cairo_clip(cr);
    cairo_set_line_width(cr, 2.0);
    cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
    cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
    for (int s = c->nseries - 1; s >= 0; s--) {      /* seria 1 na wierzchu */
        const chart_series_t *se = &c->series[s];
        int started = 0;
        double px = 0, py = 0;
        cairo_new_path(cr);
        for (int i = 0; i < se->n; i++) {
            double x = se->x ? se->x[i] : i, y = se->y[i];
            if (!isfinite(x) || !isfinite(y))
                continue;
            px = map_x(&r, &ax, x);
            py = map_y(&r, &ay, y);
            if (!started) {
                cairo_move_to(cr, px, py);
                started = 1;
            } else {
                cairo_line_to(cr, px, py);
            }
        }
        set_rgb(cr, se->color);
        cairo_stroke(cr);
        if (started && se->n == 1) {
            cairo_arc(cr, px, py, 4, 0, 2 * M_PI);
            cairo_fill(cr);
        }
        if (started) {
            lab_y[s] = py;
            lab_ok[s] = 1;
        }
    }
    cairo_restore(cr);

    if (direct) {
        /* Bezpośrednie etykiety przy końcach linii, rozsunięte o min. 14 px. */
        int idx[CHART_MAX_SERIES], k = 0;
        for (int s = 0; s < c->nseries; s++)
            if (lab_ok[s])
                idx[k++] = s;
        for (int a = 1; a < k; a++)
            for (int b = a; b > 0 && lab_y[idx[b]] < lab_y[idx[b - 1]]; b--) {
                int t = idx[b];
                idx[b] = idx[b - 1];
                idx[b - 1] = t;
            }
        double pos[CHART_MAX_SERIES];
        for (int a = 0; a < k; a++) {
            pos[a] = lab_y[idx[a]];
            if (a > 0 && pos[a] < pos[a - 1] + 14)
                pos[a] = pos[a - 1] + 14;
        }
        if (k > 0 && pos[k - 1] > r.y1) {
            double shift = pos[k - 1] - r.y1;
            for (int a = 0; a < k; a++)
                pos[a] -= shift;
        }
        use_font(cr, 10.5, 0);
        cairo_set_line_width(cr, 2.0);
        for (int a = 0; a < k; a++) {
            const chart_series_t *se = &c->series[idx[a]];
            set_rgb(cr, se->color);
            cairo_move_to(cr, r.x1 + 5, pos[a]);
            cairo_line_to(cr, r.x1 + 13, pos[a]);
            cairo_stroke(cr);
            set_rgb(cr, COL_INK2);
            text_at(cr, r.x1 + 17, pos[a] + 3.5, se->name ? se->name : "", 0);
        }
    }
}

/* ======================= wykres słupkowy pionowy ======================= */

static double series_val(const chart_series_t *s, int i)
{
    if (i >= s->n || !s->y)
        return 0;
    double v = s->y[i];
    return (isfinite(v) && v > 0) ? v : 0;
}

static void render_bar(cairo_t *cr, const chart_t *c, double w, double h, double top)
{
    int ncat = c->ncat, ns = c->nseries;
    double vmax = 0;
    for (int i = 0; i < ncat; i++) {
        double sum = 0;
        for (int s = 0; s < ns; s++) {
            double v = series_val(&c->series[s], i);
            sum += v;
            if (!c->stacked && v > vmax)
                vmax = v;
        }
        if (c->stacked && sum > vmax)
            vmax = sum;
    }
    if (ncat <= 0 || ns <= 0 || vmax <= 0) {
        draw_empty(cr, w, h, top);
        return;
    }

    axis_t ay;
    axis_linear(&ay, 0, vmax, 6);
    double lw = tick_label_width(cr, &ay, c->yfmt);
    rect_t r = { PAD + (c->ylabel ? 20 : 0) + lw + 8, top + 6, w - PAD,
                 h - (c->xlabel ? 56 : 40) };
    draw_y_grid(cr, &r, &ay, c->yfmt);
    draw_axis_titles(cr, c, &r, h);

    double slot = (r.x1 - r.x0) / ncat;
    double gw = slot * 0.72;
    double bw = c->stacked ? gw : (gw - 2.0 * (ns - 1)) / ns;
    if (bw < 1)
        bw = 1;

    for (int i = 0; i < ncat; i++) {
        double gx = r.x0 + i * slot + (slot - gw) / 2;
        if (c->stacked) {
            int topmost = -1;
            for (int s = 0; s < ns; s++)
                if (series_val(&c->series[s], i) > 0)
                    topmost = s;
            double base = 0;
            for (int s = 0; s < ns; s++) {
                double v = series_val(&c->series[s], i);
                if (v <= 0)
                    continue;
                double y0 = map_y(&r, &ay, base), y1 = map_y(&r, &ay, base + v);
                path_bar_v(cr, gx, y1, gw, y0 - y1, s == topmost ? 4 : 0);
                set_rgb(cr, c->series[s].color);
                cairo_fill(cr);
                if (s != topmost) {            /* odstęp między segmentami */
                    set_rgb(cr, COL_SURFACE);
                    cairo_set_line_width(cr, 2.0);
                    cairo_move_to(cr, gx, y1);
                    cairo_line_to(cr, gx + gw, y1);
                    cairo_stroke(cr);
                }
                base += v;
            }
        } else {
            for (int s = 0; s < ns; s++) {
                double v = series_val(&c->series[s], i);
                if (v <= 0)
                    continue;
                double x = gx + s * (bw + 2.0);
                double y1 = map_y(&r, &ay, v);
                path_bar_v(cr, x, y1, bw, r.y1 - y1, 4);
                set_rgb(cr, c->series[s].color);
                cairo_fill(cr);
            }
        }
        if (c->categories && c->categories[i]) {
            char lab[128];
            use_font(cr, 10.5, 0);
            set_rgb(cr, COL_INK2);
            fit_text(cr, c->categories[i], slot - 4, lab, sizeof lab);
            text_at(cr, r.x0 + i * slot + slot / 2, r.y1 + 17, lab, 1);
        }
    }
    set_rgb(cr, COL_AXIS);
    cairo_set_line_width(cr, 1.0);
    cairo_move_to(cr, r.x0, floor(r.y1) + 0.5);
    cairo_line_to(cr, r.x1, floor(r.y1) + 0.5);
    cairo_stroke(cr);
}

/* ======================= wykres słupkowy poziomy ======================= */
/* Serie są zawsze kumulowane (np. dane wysłane + odebrane). */

static void render_hbar(cairo_t *cr, const chart_t *c, double w, double h, double top)
{
    int ncat = c->ncat, ns = c->nseries;
    double vmax = 0;
    for (int i = 0; i < ncat; i++) {
        double sum = 0;
        for (int s = 0; s < ns; s++)
            sum += series_val(&c->series[s], i);
        if (sum > vmax)
            vmax = sum;
    }
    if (ncat <= 0 || ns <= 0 || vmax <= 0) {
        draw_empty(cr, w, h, top);
        return;
    }

    char lab[256], buf[64];
    use_font(cr, 10.5, 0);
    double labw = 0;
    for (int i = 0; i < ncat; i++)
        if (c->categories && c->categories[i])
            labw = PA_MAX(labw, text_width(cr, c->categories[i]));
    labw = PA_MIN(labw, w * 0.36);

    double valspace = 10;
    if (c->value_labels) {
        fmt_value(vmax, c->yfmt, buf, sizeof buf);
        valspace = text_width(cr, buf) + 18;
    }
    axis_t ax;
    axis_linear(&ax, 0, vmax, 5);
    rect_t r = { PAD + labw + 10, top + 4, w - PAD - valspace, h - (c->xlabel ? 50 : 32) };

    draw_x_ticks(cr, &r, &ax, c->yfmt, 1);
    draw_axis_titles(cr, c, &r, h);

    double slot = (r.y1 - r.y0) / ncat;
    double th = PA_MIN(slot * 0.68, 26.0);
    for (int i = 0; i < ncat; i++) {
        double cy = r.y0 + i * slot + slot / 2;
        if (c->categories && c->categories[i]) {
            use_font(cr, 10.5, 0);
            set_rgb(cr, COL_INK2);
            fit_text(cr, c->categories[i], labw, lab, sizeof lab);
            text_at(cr, r.x0 - 10, cy + 3.5, lab, 2);
        }
        int topmost = -1;
        double sum = 0;
        for (int s = 0; s < ns; s++) {
            double v = series_val(&c->series[s], i);
            if (v > 0)
                topmost = s;
            sum += v;
        }
        double base = 0;
        for (int s = 0; s < ns; s++) {
            double v = series_val(&c->series[s], i);
            if (v <= 0)
                continue;
            double x0 = map_x(&r, &ax, base), x1 = map_x(&r, &ax, base + v);
            if (x1 - x0 < 1.0)
                x1 = x0 + 1.0;
            path_bar_h(cr, x0, cy - th / 2, x1 - x0, th, s == topmost ? 4 : 0);
            set_rgb(cr, c->series[s].color);
            cairo_fill(cr);
            if (s != topmost) {
                set_rgb(cr, COL_SURFACE);
                cairo_set_line_width(cr, 2.0);
                cairo_move_to(cr, x1, cy - th / 2);
                cairo_line_to(cr, x1, cy + th / 2);
                cairo_stroke(cr);
            }
            base += v;
        }
        if (c->value_labels && sum > 0) {
            use_font(cr, 10, 0);
            set_rgb(cr, COL_INK2);
            fmt_value(sum, c->yfmt, buf, sizeof buf);
            text_at(cr, map_x(&r, &ax, sum) + 6, cy + 3.5, buf, 0);
        }
    }
    set_rgb(cr, COL_AXIS);
    cairo_set_line_width(cr, 1.0);
    cairo_move_to(cr, floor(r.x0) + 0.5, r.y0);
    cairo_line_to(cr, floor(r.x0) + 0.5, r.y1);
    cairo_stroke(cr);
}

/* ======================= wykres punktowy ======================= */

static void render_scatter(cairo_t *cr, const chart_t *c, double w, double h, double top)
{
    double xmin = INFINITY, xmax = -INFINITY, ymin = INFINITY, ymax = -INFINITY;
    int any = 0;
    for (int s = 0; s < c->nseries; s++) {
        const chart_series_t *se = &c->series[s];
        for (int i = 0; i < se->n; i++) {
            double x = se->x[i], y = se->y[i];
            if (!isfinite(x) || !isfinite(y))
                continue;
            if ((c->log_x && x <= 0) || (c->log_y && y <= 0))
                continue;
            any = 1;
            xmin = PA_MIN(xmin, x);
            xmax = PA_MAX(xmax, x);
            ymin = PA_MIN(ymin, y);
            ymax = PA_MAX(ymax, y);
        }
    }
    if (!any) {
        draw_empty(cr, w, h, top);
        return;
    }
    axis_t ax, ay;
    if (c->log_x)
        axis_logscale(&ax, xmin, xmax);
    else
        axis_linear(&ax, PA_MIN(xmin, 0), xmax, 7);
    if (c->log_y)
        axis_logscale(&ay, ymin, ymax);
    else
        axis_linear(&ay, PA_MIN(ymin, 0), ymax, 6);

    double lw = tick_label_width(cr, &ay, c->yfmt);
    rect_t r = { PAD + (c->ylabel ? 20 : 0) + lw + 8, top + 6, w - PAD,
                 h - (c->xlabel ? 52 : 36) };
    draw_y_grid(cr, &r, &ay, c->yfmt);
    draw_x_ticks(cr, &r, &ax, c->xfmt, 1);
    draw_axis_titles(cr, c, &r, h);

    cairo_save(cr);
    cairo_rectangle(cr, r.x0 - 5, r.y0 - 5, r.x1 - r.x0 + 10, r.y1 - r.y0 + 10);
    cairo_clip(cr);
    cairo_set_line_width(cr, 1.0);
    for (int s = c->nseries - 1; s >= 0; s--) {
        const chart_series_t *se = &c->series[s];
        for (int i = 0; i < se->n; i++) {
            double x = se->x[i], y = se->y[i];
            if (!isfinite(x) || !isfinite(y))
                continue;
            if ((c->log_x && x <= 0) || (c->log_y && y <= 0))
                continue;
            double px = map_x(&r, &ax, x), py = map_y(&r, &ay, y);
            cairo_new_path(cr);
            cairo_arc(cr, px, py, 4.0, 0, 2 * M_PI);
            set_rgba(cr, se->color, 0.75);
            cairo_fill_preserve(cr);
            set_rgb(cr, COL_SURFACE);       /* pierścień oddzielający punkty */
            cairo_stroke(cr);
        }
    }
    cairo_restore(cr);
}

/* ======================= API ======================= */

void chart_render(cairo_t *cr, const chart_t *c, double w, double h)
{
    cairo_save(cr);
    cairo_rectangle(cr, 0, 0, w, h);
    cairo_clip(cr);
    set_rgb(cr, COL_SURFACE);
    cairo_rectangle(cr, 0, 0, w, h);
    cairo_fill(cr);

    double top = draw_header(cr, c, w);
    switch (c->type) {
    case CH_LINE:    render_line(cr, c, w, h, top); break;
    case CH_BAR:     render_bar(cr, c, w, h, top); break;
    case CH_HBAR:    render_hbar(cr, c, w, h, top); break;
    case CH_SCATTER: render_scatter(cr, c, w, h, top); break;
    }
    cairo_restore(cr);
}

int chart_write_png(const chart_t *c, const char *path, double scale)
{
    int W = (int)(CHART_W * scale), H = (int)(CHART_H * scale);
    cairo_surface_t *s = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, W, H);
    if (cairo_surface_status(s) != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(s);
        return -1;
    }
    cairo_t *cr = cairo_create(s);
    cairo_scale(cr, scale, scale);
    chart_render(cr, c, CHART_W, CHART_H);
    cairo_destroy(cr);
    cairo_status_t st = cairo_surface_write_to_png(s, path);
    cairo_surface_destroy(s);
    return st == CAIRO_STATUS_SUCCESS ? 0 : -1;
}
