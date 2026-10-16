# Builds go to build/ (override with BUILD=dir). `make` builds the engine without libpcap,
# `make dpi_engine_live` adds live capture (needs libpcap headers: libpcap-dev / Xcode tools).
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -pthread
INC      := -I include
BUILD    ?= build

CORE := src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp \
        src/content_filter.cpp src/signature_engine.cpp src/ja3.cpp src/packet_source.cpp

all: $(BUILD)/dpi_engine

$(BUILD)/dpi_engine: src/dpi_mt.cpp $(CORE) $(wildcard include/*.h)
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) $(INC) -o $@ src/dpi_mt.cpp $(CORE)

dpi_engine_live: $(BUILD)/dpi_engine_live
$(BUILD)/dpi_engine_live: src/dpi_mt.cpp $(CORE) $(wildcard include/*.h)
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) $(INC) -DHAVE_PCAP -o $@ src/dpi_mt.cpp $(CORE) -lpcap

unit-test: tests/unit_tests.cpp $(CORE)
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) $(INC) -o $(BUILD)/unit_tests tests/unit_tests.cpp src/ja3.cpp src/signature_engine.cpp src/content_filter.cpp
	$(BUILD)/unit_tests

test: unit-test
	bash tests/check_fp_distribution.sh
	bash tests/check_features.sh

clean:
	rm -rf $(BUILD)

.PHONY: all dpi_engine_live unit-test test clean
