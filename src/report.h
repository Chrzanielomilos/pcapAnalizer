/*
 * report.h - generator dokumentów PDF (cairo-pdf): raport analizy dla
 * każdego pliku pcap oraz jednorazowa dokumentacja narzędzia.
 */
#ifndef PA_REPORT_H
#define PA_REPORT_H

#include "analyzer.h"
#include "figures.h"

/* Nazwa pliku dokumentacji (architektura i metody analizy), zapisywanego
 * raz na uruchomienie w głównym katalogu wynikowym. */
#define DOC_FILE_NAME "dokumentacja_narzedzia.pdf"

/* Raport z wynikami analizy jednego pliku.
 * png_written != 0: wykresy PNG zostały zapisane obok raportu. */
int report_write_pdf(const analysis_t *a, const figure_set_t *fs, const char *path,
                     int png_written);

/* Dokumentacja narzędzia: architektura, moduły, zależności, metody analizy
 * i progi detektorów obowiązujące w danym uruchomieniu. */
int report_write_doc(const config_t *cfg, const char *path);

#endif
