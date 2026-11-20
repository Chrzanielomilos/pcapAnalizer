/*
 * report.h - generator raportu PDF (cairo-pdf).
 */
#ifndef PA_REPORT_H
#define PA_REPORT_H

#include "analyzer.h"
#include "figures.h"

/* png_written != 0: wykresy PNG zostały zapisane obok raportu. */
int report_write_pdf(const analysis_t *a, const figure_set_t *fs, const char *path,
                     int png_written);

#endif
