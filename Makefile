CXX      = g++
CXXFLAGS = -std=c++17 -O2 -Wall -I include
SRCS     = src/pcap_reader.cpp src/packet_parser.cpp \
	   src/sni_extractor.cpp src/types.cpp \
	   src/rule_manager.cpp

all: dpi_simple dpi_engine

dpi_simple: $(SRCS) src/main_working.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^
	@echo "Built dpi_simple"

dpi_engine: $(SRCS) src/dpi_mt.cpp
	$(CXX) $(CXXFLAGS) -pthread -o $@ $^
	@echo "Built dpi_engine"

dpi_test: $(SRCS) src/test_dpi.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^
	@echo "Built dpi_test"

clean:
	rm -f dpi_simple dpi_engine dpi_test
