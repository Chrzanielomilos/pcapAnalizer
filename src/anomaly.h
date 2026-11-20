/*
 * anomaly.h - detektory nieprawidłowości uruchamiane po zakończeniu
 * przetwarzania pakietów (na przepływach, szeregach czasowych i DNS).
 */
#ifndef PA_ANOMALY_H
#define PA_ANOMALY_H

#include "analyzer.h"

/* Uruchamia wszystkie detektory i sortuje wyniki wg ważności. */
void anomaly_detect(analysis_t *a);

#endif
