# Decyzje architektoniczne pcapanalyzer

Poniższe decyzje mają status **wdrożone**. Opisują sposób działania analizatora oraz konsekwencje tych wyborów dla interpretacji wyników.

## ADR-001. Jednoprzebiegowy odczyt pakietów

**Kontekst.** Duży plik pcap może zawierać wiele pakietów należących do tych samych przepływów. Do obliczenia wolumenu ruchu, czasu uzgadniania TCP i liczby retransmisji wystarczają liczniki oraz stan połączeń.

**Decyzja.** Dla każdego pliku analizator odczytuje przez libpcap po jednym pakiecie, dekoduje go i aktualizuje stan przepływów, statystyki hostów oraz szeregi czasowe. Gdy zapis wykracza poza zakres szeregu, program scala pary sąsiednich przedziałów i podwaja ich szerokość. Po odczycie detektory korzystają ze zgromadzonych wyników. [Odczyt i agregacja](../../src/analyzer.c) · [Scalanie przedziałów](../../src/stats.c)

**Konsekwencje.** Zużycie pamięci zależy m.in. od liczby przepływów i hostów. Scalanie zachowuje sumy pakietów i bajtów, ale obniża rozdzielczość czasową. Aby zbadać szczegóły pojedynczego pakietu po zakończeniu analizy, trzeba ponownie odczytać plik źródłowy.

## ADR-002. Dwukierunkowe przepływy TCP i UDP

**Kontekst.** Pomiar czasu uzgadniania TCP wymaga powiązania pakietów klienta z odpowiedziami serwera. Raport pokazuje też, jaka część ruchu przypada na każdy kierunek.

**Decyzja.** Klucz w tablicy przepływów składa się z protokołu transportowego i dwóch par (adres IP, port), zapisanych w ustalonej kolejności. Pakiety wysyłane w obu kierunkach trafiają do wspólnego rekordu z osobnymi licznikami dla każdego kierunku. Gdy kolejny pakiet pojawi się po przerwie dłuższej niż `idle_timeout`, rozpoczyna nowy rekord. W TCP nowy SYN bez ACK rozpoczyna także nowy rekord po RST lub po zaobserwowaniu FIN z obu stron. [Tablica przepływów i ustalanie kierunku](../../src/flow.c)

**Konsekwencje.** Jeden rekord pozwala prześledzić uzgadnianie TCP lub sprawdzić, czy ruch UDP był dwukierunkowy. Długa przerwa może podzielić jedną sesję aplikacji na kilka przepływów. Dla UDP i dla zapisu TCP rozpoczynającego się w trakcie połączenia przypisanie ról klienta i serwera opiera się na portach i kierunku pierwszego zaobserwowanego pakietu.

## ADR-003. Dokumentacja narzędzia oddzielona od raportów

**Kontekst.** Jedno wywołanie programu może objąć kilka plików pcap. Opis architektury i metod analizy jest taki sam dla każdego pliku, więc powtarzanie go w każdym raporcie wydłużało dokumenty i dublowało treść.

**Decyzja.** Program generuje wyłącznie wyniki analizy. W podkatalogu każdego analizowanego pliku powstaje `raport.pdf` z wynikami i objaśnieniem prezentowanych danych, a obok niego wykresy PNG, `przeplywy.csv` i `podsumowanie.txt`. Opis architektury i metod analizy znajduje się w statycznym pliku `dokumentacja_narzedzia.pdf` w katalogu głównym projektu, który jest utrzymywany niezależnie od programu: program go nie tworzy ani nie aktualizuje. Progi detektorów obowiązujące w danym wywołaniu wypisuje `pcapanalyzer -L` uruchomione z tymi samymi opcjami `-T`, podanymi przed `-L`. [Obsługa wielu plików](../../src/main.c) · [Zawartość raportu](../../src/report.c) · [Progi detektorów](../../src/analyzer.c)

**Konsekwencje.** Raporty są krótsze i zawierają tylko treści dotyczące analizowanego pliku. Dokumentacja nie powstaje automatycznie, więc po zmianie metod analizy lub domyślnych progów trzeba ją zaktualizować ręcznie. Progi opisane w dokumentacji to wartości domyślne z chwili jej przygotowania. Jeśli analizę uruchomiono z opcją `-T`, faktycznie użytych progów nie zapisuje ani raport, ani pozostałe pliki wynikowe, dlatego trzeba je odnotować osobno, np. jako wynik `pcapanalyzer -T … -L`. Przy przekazywaniu raportu warto dołączyć dokumentację i tę informację.
