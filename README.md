# pcapanalyzer — analiza komunikacji TCP/UDP z plików pcap

Narzędzie wiersza poleceń dla Linuksa (Ubuntu), napisane w C11. Analizuje ruch TCP i UDP
zapisany w plikach `.pcap`/`.pcapng` i dla każdego pliku generuje:

* **raport PDF** ze statystykami, tabelami, wykresami wektorowymi, listą wykrytych
  nieprawidłowości i opisem prezentowanych danych,
* **12 wykresów PNG** (1600×900),
* **listę przepływów CSV** i **podsumowanie tekstowe**.

Zależności: `libpcap`, `cairo` (PNG + PDF), `libm` i czcionka DejaVu — wszystkie są
w standardowych repozytoriach Ubuntu.

## Instalacja i kompilacja

```bash
sudo apt-get install -y build-essential pkg-config libpcap-dev libcairo2-dev fonts-dejavu-core
# albo: make deps
make
```

## Użycie

```bash
./pcapanalyzer [opcje] plik.pcap [plik2.pcap ...]

./pcapanalyzer -o wyniki tests/pcap/02_port_scan.pcap
./pcapanalyzer -T scan_ports=100 -T spike_k=8 zapis.pcapng
./pcapanalyzer -L            # lista progów detektorów z wartościami domyślnymi
```

| Opcja | Znaczenie |
|---|---|
| `-o, --output KATALOG` | katalog wynikowy (domyślnie `wyniki`); dla każdego pliku powstaje podkatalog o nazwie pliku |
| `-t, --top N` | długość list rankingowych (domyślnie 10) |
| `-T, --threshold K=W` | zmiana progu detektora (można powtarzać) |
| `-L, --list-thresholds` | wypisuje dostępne progi |
| `-n, --no-png` / `-c, --no-csv` | bez wykresów PNG / bez pliku CSV |
| `-q, --quiet` | bez podsumowania na stdout |

Kody wyjścia: `0` — sukces, `1` — błąd przetwarzania pliku, `2` — błędne argumenty.

Wynik dla `./pcapanalyzer -o wyniki zapis.pcap`:

```
wyniki/
└── zapis/
    ├── raport.pdf
    ├── podsumowanie.txt
    ├── przeplywy.csv
    ├── 01_przeplywnosc.png          ├── 07_stany_przeplywow.png
    ├── 02_natezenie_pakietow.png    ├── 08_przeplywy_czas_wolumen.png
    ├── 03_protokoly.png             ├── 09_rtt_uzgadniania.png
    ├── 04_rozmiary_pakietow.png     ├── 10_flagi_tcp.png
    ├── 05_najaktywniejsze_hosty.png ├── 11_uzgadnianie_syn.png
    └── 06_uslugi.png                └── 12_problemy_tcp.png
```

Raport pliku zawiera sekcje: 1. Podsumowanie, 2. Statystyki ruchu, 3. Charakterystyka
komunikacji, 4. Analiza protokołu TCP, 5. Analiza DNS, 6. Wykryte nieprawidłowości,
7. Opis prezentowanych danych, Załącznik A. Pliki wynikowe.

## Co analizuje

* **Dekodowanie**: Ethernet (802.1Q/QinQ), Linux SLL/SLL2, loopback, raw IP; IPv4 (suma
  kontrolna, fragmentacja), IPv6 (nagłówki rozszerzeń); TCP (opcje MSS/WS/SACK), UDP.
* **Statystyki ruchu**: wolumen, przepływność i natężenie w czasie, udział protokołów,
  rozkład rozmiarów ramek, najaktywniejsze hosty i usługi.
* **Przepływy**: dwukierunkowe przepływy (piątka), klient/serwer, stan połączenia TCP
  (zakończone, zerwane, półotwarte, odrzucone, bez odpowiedzi…).
* **Jakość TCP**: czas uzgadniania (RTT), retransmisje, segmenty poza kolejnością, luki,
  zduplikowane ACK, zerowe okno, keep-alive.
* **DNS**: zapytania/odpowiedzi, NXDOMAIN, typy zapytań, długość i entropia nazw.
* **Nieprawidłowości**: skanowanie pionowe i poziome, SYN flood, UDP flood, niedozwolone
  flagi TCP (NULL/XMAS/SYN+FIN/SYN+RST/FIN bez ACK), tunelowanie DNS, wysoki udział
  NXDOMAIN, beaconing (okresowa komunikacja), retransmisje, zerowe okno, zrywanie
  połączeń RST, skoki natężenia (mediana + MAD), problemy z jakością danych.

Interpretacja prezentowanych danych znajduje się w sekcji 7 każdego raportu, a aktualne
progi detektorów można wypisać poleceniem `./pcapanalyzer -L`.

## Architektura

```
plik.pcap ─► odczyt (libpcap) ─► dekoder L2–L4 ─► tablica przepływów
                                      │                   │
                                      ▼                   ▼
                          agregatory statystyk ◄── przetwarzanie końcowe
                                      │
                                      ▼
                   detektory anomalii ─► wykresy (cairo) ─► PDF / PNG / CSV
```

| Plik | Odpowiedzialność |
|---|---|
| `src/main.c` | CLI, obsługa wielu plików, zapis wyników |
| `src/analyzer.c/.h` | odczyt pakietów, agregacja, przetwarzanie końcowe, progi, CSV |
| `src/decoder.c/.h` | dekodowanie nagłówków L2–L4 z kontrolą granic bufora |
| `src/flow.c/.h` | tablica mieszająca przepływów, stan i analiza sekwencji TCP |
| `src/stats.c/.h` | adaptacyjne szeregi czasowe, hosty, histogramy, DNS |
| `src/anomaly.c/.h` | detektory nieprawidłowości |
| `src/charts.c/.h` | silnik wykresów cairo (liniowe, słupkowe, punktowe) |
| `src/figures.c/.h` | definicje 12 wykresów (wspólne dla PNG i PDF) |
| `src/report.c/.h` | składanie raportu PDF (cairo-pdf) |
| `src/util.c`, `src/common.h` | formatowanie, adresy, alokacja |
| `tests/run_tests.sh` | testy funkcjonalne |

Analiza jest jednoprzebiegowa i strumieniowa: treść pakietów nie jest przechowywana,
a pamięć zależy od liczby przepływów i hostów, nie od rozmiaru pliku.

### Decyzje architektoniczne (ADR)

Każdy wpis opisuje kontekst decyzji, jej uzasadnienie i konsekwencje dla analizy ruchu lub interpretacji raportów.

* [ADR-001. Jednoprzebiegowy odczyt pakietów](docs/adr/ADR.md#adr-001-jednoprzebiegowy-odczyt-pakietów)
* [ADR-002. Dwukierunkowe przepływy TCP i UDP](docs/adr/ADR.md#adr-002-dwukierunkowe-przepływy-tcp-i-udp)
* [ADR-003. Wspólna dokumentacja dla raportów z jednego uruchomienia](docs/adr/ADR.md#adr-003-wspólna-dokumentacja-dla-raportów-z-jednego-uruchomienia)

## Testowe pliki pcap

Katalog `tests/pcap` zawiera syntetyczne zapisy z poprawnymi sumami kontrolnymi.

| Plik | Scenariusz | Oczekiwane wyniki |
|---|---|---|
| `01_normal_traffic.pcap` | 60 s ruchu biurowego: HTTP/HTTPS, DNS, NTP, SSH w VLAN 100, IPv6, ICMP, ARP | brak nieprawidłowości |
| `02_port_scan.pcap` | skan SYN portów 1–1024, skan poziomy /24 na porcie 445, skany NULL/XMAS/FIN | skanowanie pionowe i poziome, niedozwolone flagi |
| `03_syn_flood.pcap` | 6000 SYN/6 s z losowych adresów na 192.168.1.80:80 | SYN flood, skok natężenia |
| `04_udp_flood_dns_tunnel.pcap` | UDP flood 1000 pkt/s na 192.168.1.100:27015, tunel DNS (TXT, base32) | UDP flood, tunelowanie DNS |
| `05_tcp_problems.pcap` | pobieranie 1,2 MB z 7% utratą, zmiana kolejności, zerowe okno, sesje zrywane RST, połączenia co 10 s | retransmisje, zerowe okno, RST, beaconing |
| `06_linux_sll_ipv6.pcap` | zapis typu Linux cooked capture (SLL), głównie IPv6 | brak nieprawidłowości |

```bash
make test     # analiza wszystkich plików i sprawdzenie oczekiwanych wyników
make demo     # raporty dla wszystkich plików testowych w katalogu wyniki/
```

## Ograniczenia

* Analizowane są nagłówki; treść szyfrowana nie jest interpretowana, a usługi
  rozpoznawane są po numerach portów.
* Wyniki analizy TCP zależą od miejsca przechwytywania ruchu.
* Progi detektorów są heurystyczne i można je dostosować opcją `-T`.
* Fragmenty IP nie są składane.
