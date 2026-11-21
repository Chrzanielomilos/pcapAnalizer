# pcapanalyzer - analiza komunikacji TCP/UDP z plików pcap
#
#   make            kompilacja programu
#   make deps       instalacja zależności (Ubuntu/Debian, wymaga sudo)
#   make test       testy na dołączonych plikach pcap
#   make demo       raporty dla wszystkich plików testowych (katalog wyniki/)
#   make clean      usunięcie artefaktów kompilacji i wyników

CC      ?= gcc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -Wshadow -Wno-unused-parameter
PKG_CONFIG ?= pkg-config

CAIRO_CFLAGS := $(shell $(PKG_CONFIG) --cflags cairo)
CAIRO_LIBS   := $(shell $(PKG_CONFIG) --libs cairo)
LDLIBS       += $(CAIRO_LIBS) -lpcap -lm

BIN  := pcapanalyzer
SRC  := $(wildcard src/*.c)
OBJ  := $(SRC:src/%.c=build/%.o)
HDR  := $(wildcard src/*.h)

.PHONY: all deps test demo clean

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

build/%.o: src/%.c $(HDR) | build
	$(CC) $(CFLAGS) $(CAIRO_CFLAGS) -c -o $@ $<

build:
	mkdir -p build

test: $(BIN)
	bash tests/run_tests.sh

demo: $(BIN)
	./$(BIN) -o wyniki tests/pcap/*.pcap

deps:
	sudo apt-get update
	sudo apt-get install -y build-essential pkg-config libpcap-dev libcairo2-dev fonts-dejavu-core

clean:
	rm -rf build $(BIN) wyniki tests/out
