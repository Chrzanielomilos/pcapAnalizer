#!/usr/bin/env bash
# Testy funkcjonalne pcapanalyzer na dołączonych plikach pcap.
# Uruchomienie: make test   (lub: bash tests/run_tests.sh)
set -u
cd "$(dirname "$0")/.."

BIN=./pcapanalyzer
OUT=tests/out
PCAP=tests/pcap
pass=0
fail=0

if [ ! -x "$BIN" ]; then
    echo "Brak programu $BIN - uruchom najpierw: make"
    exit 1
fi
rm -rf "$OUT"
mkdir -p "$OUT"

ok()  { echo "  OK    $1"; pass=$((pass + 1)); }
bad() { echo "  BŁĄD  $1"; fail=$((fail + 1)); }

# has <opis> <wzorzec>      - podsumowanie zawiera wzorzec (grep -E)
has()   { if grep -Eq -- "$2" "$SUM"; then ok "$1"; else bad "$1"; fi; }
# hasnt <opis> <wzorzec>    - podsumowanie NIE zawiera wzorca
hasnt() { if grep -Eq -- "$2" "$SUM"; then bad "$1"; else ok "$1"; fi; }

# analyze <plik.pcap> - uruchamia analizę i sprawdza komplet plików wynikowych
analyze() {
    local name="$1" stem="${1%.pcap}"
    echo "== $name"
    DIR="$OUT/$stem"
    SUM="$DIR/podsumowanie.txt"
    if "$BIN" -q -o "$OUT" "$PCAP/$name"; then ok "kod wyjścia 0"; else bad "kod wyjścia 0"; fi
    if [ -s "$DIR/raport.pdf" ] && head -c 5 "$DIR/raport.pdf" | grep -q '%PDF-'; then
        ok "raport PDF"
    else
        bad "raport PDF"
    fi
    local npng
    npng=$(ls "$DIR"/*.png 2>/dev/null | wc -l)
    if [ "$npng" -eq 12 ]; then ok "12 wykresów PNG"; else bad "12 wykresów PNG (jest: $npng)"; fi
    if [ -s "$DIR/przeplywy.csv" ] && [ "$(wc -l < "$DIR/przeplywy.csv")" -gt 1 ]; then
        ok "lista przepływów CSV"
    else
        bad "lista przepływów CSV"
    fi
    [ -s "$SUM" ] || SUM=/dev/null
}

analyze 01_normal_traffic.pcap
hasnt "brak nieprawidłowości o poziomie WYSOKI" '\[WYSOKI\]'
hasnt "brak nieprawidłowości o poziomie ŚREDNI" '\[ŚREDNI\]'
has   "rozpoznany ruch IPv6" 'IPv6: [1-9]'

analyze 02_port_scan.pcap
has "skanowanie pionowe 10.10.10.66 → 192.168.1.20" '\[WYSOKI\] Skanowanie portów TCP: 10\.10\.10\.66 → 192\.168\.1\.20'
has "skanowanie poziome tcp/445" '\[WYSOKI\] Skanowanie poziome tcp/445'
has "skanowanie NULL" 'NULL \(brak flag\)'
has "skanowanie XMAS" 'XMAS'
has "skanowanie FIN" 'FIN bez ACK'

analyze 03_syn_flood.pcap
has "SYN flood na 192.168.1.80" '\[WYSOKI\] SYN flood na 192\.168\.1\.80'
has "skok natężenia ruchu" 'Gwałtowny wzrost natężenia'

analyze 04_udp_flood_dns_tunnel.pcap
has "UDP flood na 192.168.1.100" '\[WYSOKI\] UDP flood na 192\.168\.1\.100'
has "tunelowanie DNS z 192.168.1.33" 'tunelowanie DNS z hosta 192\.168\.1\.33'

analyze 05_tcp_problems.pcap
has "podwyższony poziom retransmisji" 'Podwyższony poziom retransmisji TCP'
has "przepływ z retransmisjami" 'Przepływy TCP z dużą liczbą retransmisji'
has "zerowe okno TCP" 'Zerowe okno odbiorcze'
has "zrywanie połączeń RST" 'zrywanych przez RST'
has "okresowa komunikacja (beaconing)" '\[ŚREDNI\] Okresowa komunikacja 192\.168\.1\.57 → 185\.199\.110\.5'

analyze 06_linux_sll_ipv6.pcap
has   "typ łącza Linux SLL" 'LINUX_SLL'
has   "ruch IPv6" 'IPv6: [1-9]'
hasnt "brak nieprawidłowości o poziomie WYSOKI" '\[WYSOKI\]'

echo "== dokumentacja narzędzia (jeden plik na uruchomienie)"
if [ -s "$OUT/dokumentacja_narzedzia.pdf" ] && head -c 5 "$OUT/dokumentacja_narzedzia.pdf" | grep -q '%PDF-'; then
    ok "dokumentacja w głównym katalogu wynikowym"
else
    bad "dokumentacja w głównym katalogu wynikowym"
fi
"$BIN" -q -o "$OUT/wiele" "$PCAP/01_normal_traffic.pcap" "$PCAP/06_linux_sll_ipv6.pcap"
ndoc=$(find "$OUT/wiele" -name 'dokumentacja_narzedzia.pdf' | wc -l)
if [ "$ndoc" -eq 1 ] && [ -s "$OUT/wiele/dokumentacja_narzedzia.pdf" ]; then
    ok "dwa pliki wejściowe: dokładnie jedna dokumentacja"
else
    bad "dwa pliki wejściowe: dokładnie jedna dokumentacja (jest: $ndoc)"
fi
if command -v pdftotext >/dev/null 2>&1; then
    rtxt=$(pdftotext "$OUT/wiele/01_normal_traffic/raport.pdf" - 2>/dev/null)
    dtxt=$(pdftotext "$OUT/wiele/dokumentacja_narzedzia.pdf" - 2>/dev/null)
    if echo "$rtxt" | grep -Eq 'Architektura narzędzia|Metody analizy|Moduły programu'; then
        bad "raport bez sekcji o architekturze i metodach"
    else
        ok "raport bez sekcji o architekturze i metodach"
    fi
    if echo "$dtxt" | grep -q 'Architektura narzędzia' && echo "$dtxt" | grep -q 'Metody analizy'; then
        ok "dokumentacja zawiera architekturę i metody analizy"
    else
        bad "dokumentacja zawiera architekturę i metody analizy"
    fi
fi

echo "== odporność na błędne dane"
head -c 300000 "$PCAP/01_normal_traffic.pcap" > "$OUT/obciety.pcap"
if "$BIN" -q -o "$OUT" "$OUT/obciety.pcap" 2>/dev/null && [ -s "$OUT/obciety/raport.pdf" ]; then
    ok "obcięty plik: raport z wyników częściowych"
else
    bad "obcięty plik: raport z wyników częściowych"
fi
SUM="$OUT/obciety/podsumowanie.txt"
[ -s "$SUM" ] || SUM=/dev/null
has "obcięty plik: ostrzeżenie w podsumowaniu" 'Ostrzeżenie'
printf 'to nie jest plik pcap' > "$OUT/smieci.pcap"
"$BIN" -q -o "$OUT" "$OUT/smieci.pcap" 2>/dev/null
if [ $? -eq 1 ]; then ok "niepoprawny plik: kod wyjścia 1"; else bad "niepoprawny plik: kod wyjścia 1"; fi
"$BIN" -q -o "$OUT" "$OUT/nie_istnieje.pcap" 2>/dev/null
if [ $? -eq 1 ]; then ok "brak pliku: kod wyjścia 1"; else bad "brak pliku: kod wyjścia 1"; fi
"$BIN" -T nieznany=1 "$PCAP/01_normal_traffic.pcap" >/dev/null 2>&1
if [ $? -eq 2 ]; then ok "nieznany próg: kod wyjścia 2"; else bad "nieznany próg: kod wyjścia 2"; fi
"$BIN" -q -o "$OUT/progi" -T scan_ports=5000 -T scan_hosts=5000 "$PCAP/02_port_scan.pcap"
SUM="$OUT/progi/02_port_scan/podsumowanie.txt"
[ -s "$SUM" ] || SUM=/dev/null
hasnt "zmiana progów opcją -T wyłącza detekcję skanowania" 'Skanowanie'

# Odtwarzalność plików testowych (informacyjnie - nie wpływa na wynik testów).
if [ -f tools/pcapgen.c ] && command -v "${CC:-gcc}" >/dev/null 2>&1; then
    echo "== odtwarzalność plików testowych (tools/pcapgen)"
    if "${CC:-gcc}" -O2 -ffp-contract=off -o "$OUT/pcapgen" tools/pcapgen.c 2>/dev/null &&
       "$OUT/pcapgen" "$OUT/regen" >/dev/null; then
        for f in "$PCAP"/*.pcap; do
            if cmp -s "$f" "$OUT/regen/$(basename "$f")"; then
                echo "  OK    $(basename "$f") identyczny z wygenerowanym"
            else
                echo "  UWAGA $(basename "$f") różni się od pliku z pcapgen"
            fi
        done
    fi
fi

echo
echo "Wynik: $pass zaliczonych, $fail niezaliczonych"
[ "$fail" -eq 0 ]
