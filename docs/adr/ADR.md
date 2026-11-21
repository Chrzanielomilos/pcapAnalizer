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

## ADR-003. Wspólna dokumentacja dla raportów z jednego uruchomienia

**Kontekst.** Jedno wywołanie programu może objąć kilka plików pcap. Wyniki dotyczą poszczególnych plików, a metody analizy i ustawione progi detektorów obowiązują dla całego wywołania.

**Decyzja.** Program zapisuje `dokumentacja_narzedzia.pdf` raz w głównym katalogu wynikowym. Dokument opisuje architekturę, metody analizy i progi użyte podczas tego uruchomienia. W podkatalogu każdego analizowanego pliku powstaje `raport.pdf` z wynikami i objaśnieniem prezentowanych danych. [Obsługa wielu plików](../../src/main.c) · [Zawartość obu dokumentów](../../src/report.c)

**Konsekwencje.** Cała seria raportów korzysta z jednego opisu metod. Przy archiwizacji lub przekazywaniu pojedynczego raportu warto dołączyć wspólny PDF, aby odbiorca mógł sprawdzić progi zastosowane w analizie.
