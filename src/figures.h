/*
 * figures.h - budowa zestawu wykresów (definicji chart_t) na podstawie
 * wyników analizy. Ten sam zestaw jest zapisywany do PNG i osadzany w PDF.
 */
#ifndef PA_FIGURES_H
#define PA_FIGURES_H

#include "analyzer.h"
#include "charts.h"

enum {
    FIG_THROUGHPUT = 0,
    FIG_PPS,
    FIG_PROTO,
    FIG_SIZES,
    FIG_TALKERS,
    FIG_SERVICES,
    FIG_FLOWSTATES,
    FIG_SCATTER,
    FIG_RTT,
    FIG_FLAGS,
    FIG_HANDSHAKE,
    FIG_TCPHEALTH,
    FIG_COUNT
};

typedef struct {
    chart_t     chart;
    char        file[64];      /* nazwa pliku PNG                        */
    const char *caption;       /* podpis rysunku                          */
    const char *desc;          /* opis prezentowanych danych              */
} figure_t;

typedef struct {
    figure_t fig[FIG_COUNT];
    double   bin_width;        /* szerokość przedziału szeregów czasowych */
    void   **allocs;           /* pamięć należąca do zestawu wykresów     */
    size_t   nalloc, capalloc;
} figure_set_t;

void figures_build(figure_set_t *fs, const analysis_t *a);
void figures_free(figure_set_t *fs);
int  figures_write_png(const figure_set_t *fs, const char *dir, int verbose);

#endif
