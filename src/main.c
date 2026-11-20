/*
 * main.c - interfejs wiersza poleceń narzędzia pcapanalyzer.
 *
 * Dla każdego pliku wejściowego tworzony jest katalog <wyjście>/<nazwa>
 * zawierający raport PDF, wykresy PNG, listę przepływów CSV
 * i podsumowanie tekstowe.
 */
#include "analyzer.h"
#include "anomaly.h"
#include "figures.h"
#include "report.h"

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *outdir;
    int         no_png;
    int         no_csv;
    int         quiet;
} options_t;

static void usage(FILE *o)
{
    fprintf(o,
        "Użycie: " PA_NAME " [opcje] plik.pcap [plik2.pcap ...]\n"
        "\n"
        "Analizuje komunikację TCP i UDP zapisaną w plikach pcap/pcapng i generuje\n"
        "raport PDF, wykresy PNG, listę przepływów CSV oraz podsumowanie tekstowe.\n"
        "\n"
        "Opcje:\n"
        "  -o, --output KATALOG     katalog wynikowy (domyślnie: wyniki); dla każdego\n"
        "                           pliku tworzony jest podkatalog o nazwie pliku\n"
        "  -t, --top N              długość list rankingowych (domyślnie 10)\n"
        "  -T, --threshold K=W      zmiana progu detektora, np. -T scan_ports=100\n"
        "                           (opcję można powtarzać)\n"
        "  -L, --list-thresholds    wypisz dostępne progi i ich wartości domyślne\n"
        "  -n, --no-png             nie zapisuj wykresów PNG (tylko raport PDF)\n"
        "  -c, --no-csv             nie zapisuj listy przepływów CSV\n"
        "  -q, --quiet              nie wypisuj podsumowania na standardowe wyjście\n"
        "  -V, --version            wersja programu\n"
        "  -h, --help               ta pomoc\n"
        "\n"
        "Kod wyjścia: 0 - sukces, 1 - błąd przetwarzania co najmniej jednego pliku,\n"
        "2 - błędne argumenty.\n");
}

/* Nazwa pliku bez katalogu i rozszerzenia. */
static void file_stem(const char *path, char *out, size_t n)
{
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    snprintf(out, n, "%s", base);
    char *dot = strrchr(out, '.');
    if (dot && dot != out)
        *dot = '\0';
    if (out[0] == '\0')
        snprintf(out, n, "analiza");
}

static int process_file(const char *path, const config_t *cfg, const options_t *opt)
{
    char err[512] = "";
    analysis_t *a = xcalloc(1, sizeof *a);
    analysis_init(a, cfg);

    if (analysis_run(a, path, err, sizeof err) != 0) {
        fprintf(stderr, PA_NAME ": nie można otworzyć %s: %s\n", path, err);
        analysis_free(a);
        free(a);
        return 1;
    }
    if (a->read_warning[0])
        fprintf(stderr, PA_NAME ": %s: %s\n", path, a->read_warning);
    if (a->g.pkts == 0)
        fprintf(stderr, PA_NAME ": %s: plik nie zawiera pakietów\n", path);

    analysis_finalize(a);
    anomaly_detect(a);

    char stem[256], dir[3072], file[4096];
    file_stem(path, stem, sizeof stem);
    snprintf(dir, sizeof dir, "%s/%s", opt->outdir, stem);
    if (mkdir_p(dir) != 0) {
        fprintf(stderr, PA_NAME ": nie można utworzyć katalogu %s: %s\n", dir,
                strerror(errno));
        analysis_free(a);
        free(a);
        return 1;
    }

    int rc = 0;
    figure_set_t fs;
    figures_build(&fs, a);

    int png_ok = 0;
    if (!opt->no_png) {
        if (figures_write_png(&fs, dir, 0) == 0)
            png_ok = 1;
        else
            rc = 1;
    }

    snprintf(file, sizeof file, "%s/raport.pdf", dir);
    if (report_write_pdf(a, &fs, file, png_ok) != 0) {
        fprintf(stderr, PA_NAME ": błąd zapisu raportu %s\n", file);
        rc = 1;
    }

    if (!opt->no_csv) {
        snprintf(file, sizeof file, "%s/przeplywy.csv", dir);
        if (analysis_write_flows_csv(a, file) != 0) {
            fprintf(stderr, PA_NAME ": błąd zapisu %s\n", file);
            rc = 1;
        }
    }

    snprintf(file, sizeof file, "%s/podsumowanie.txt", dir);
    FILE *sf = fopen(file, "w");
    if (sf) {
        analysis_print_summary(a, sf);
        fclose(sf);
    } else {
        fprintf(stderr, PA_NAME ": błąd zapisu %s\n", file);
        rc = 1;
    }

    if (!opt->quiet) {
        analysis_print_summary(a, stdout);
        printf("  Wyniki zapisano w katalogu: %s\n\n", dir);
    }

    figures_free(&fs);
    analysis_free(a);
    free(a);
    return rc;
}

int main(int argc, char **argv)
{
    config_t cfg;
    options_t opt = { "wyniki", 0, 0, 0 };
    config_defaults(&cfg);

    static const struct option longopts[] = {
        {"output",          required_argument, NULL, 'o'},
        {"top",             required_argument, NULL, 't'},
        {"threshold",       required_argument, NULL, 'T'},
        {"list-thresholds", no_argument,       NULL, 'L'},
        {"no-png",          no_argument,       NULL, 'n'},
        {"no-csv",          no_argument,       NULL, 'c'},
        {"quiet",           no_argument,       NULL, 'q'},
        {"version",         no_argument,       NULL, 'V'},
        {"help",            no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int ch;
    while ((ch = getopt_long(argc, argv, "o:t:T:LncqVh", longopts, NULL)) != -1) {
        switch (ch) {
        case 'o':
            opt.outdir = optarg;
            break;
        case 't': {
            char kv[64];
            snprintf(kv, sizeof kv, "top_n=%s", optarg);
            if (config_set(&cfg, kv) != 0) {
                fprintf(stderr, PA_NAME ": niepoprawna wartość opcji --top: %s\n", optarg);
                return 2;
            }
            break;
        }
        case 'T':
            if (config_set(&cfg, optarg) != 0) {
                fprintf(stderr, PA_NAME ": niepoprawny próg: %s (lista: " PA_NAME " -L)\n",
                        optarg);
                return 2;
            }
            break;
        case 'L':
            printf("Dostępne progi detektorów (klucz = wartość domyślna):\n");
            config_print(stdout, &cfg);
            return 0;
        case 'n':
            opt.no_png = 1;
            break;
        case 'c':
            opt.no_csv = 1;
            break;
        case 'q':
            opt.quiet = 1;
            break;
        case 'V':
            printf(PA_NAME " " PA_VERSION "\n");
            return 0;
        case 'h':
            usage(stdout);
            return 0;
        default:
            usage(stderr);
            return 2;
        }
    }
    if (optind >= argc) {
        usage(stderr);
        return 2;
    }

    /* Dokumentacja narzędzia - jeden plik na uruchomienie, wspólny dla
     * wszystkich raportów. */
    int failed = 0;
    char docpath[4096];
    snprintf(docpath, sizeof docpath, "%s/%s", opt.outdir, DOC_FILE_NAME);
    if (mkdir_p(opt.outdir) != 0) {
        fprintf(stderr, PA_NAME ": nie można utworzyć katalogu %s: %s\n", opt.outdir,
                strerror(errno));
        return 1;
    }
    if (report_write_doc(&cfg, docpath) != 0) {
        fprintf(stderr, PA_NAME ": błąd zapisu dokumentacji %s\n", docpath);
        failed = 1;
    } else if (!opt.quiet) {
        printf("Dokumentacja narzędzia: %s\n\n", docpath);
    }

    for (int i = optind; i < argc; i++)
        if (process_file(argv[i], &cfg, &opt) != 0)
            failed = 1;
    cairo_debug_reset_static_data();   /* zwolnienie pamięci podręcznych cairo */
    return failed;
}
