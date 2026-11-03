# Usage: make GHIDRA_TRUNK=<path to Ghidra source checkout>
#
# Optional:
#   SLA_DIR=<dir containing libsla.a>   (defaults to the Ghidra decompiler source dir)
#   EXTRA_CXXFLAGS / EXTRA_LDFLAGS        (e.g. -I/-L for a non-system boost or nlohmann_json)

ifneq ($(filter-out clean,$(or $(MAKECMDGOALS),all)),)
ifndef GHIDRA_TRUNK
$(error GHIDRA_TRUNK is not set. Run: make GHIDRA_TRUNK=<path to Ghidra source checkout>)
endif
endif

DECOMPILER_SRC = $(GHIDRA_TRUNK)/Ghidra/Features/Decompiler/src/decompile/cpp
SLA_DIR ?= $(DECOMPILER_SRC)

CXX ?= g++
CXXFLAGS = -pipe -g -O2 -std=c++17 -Wall -Wextra -Wno-unused-parameter -pthread \
           -isystem $(DECOMPILER_SRC) $(EXTRA_CXXFLAGS)
LDFLAGS = -pthread $(EXTRA_LDFLAGS)
LIBS = $(SLA_DIR)/libsla.a -lboost_program_options -lz

OBJ = main.o state.o runner.o backends/json.o backends/sla_emulator.o

all: verifier

$(SLA_DIR)/libsla.a:
	$(error $@ not found. Build it with: make -C $(DECOMPILER_SRC) libsla.a)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -MMD -MP -c -o $@ $<

verifier: $(OBJ) $(SLA_DIR)/libsla.a
	$(CXX) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

-include $(OBJ:.o=.d)

.PHONY: all clean
clean:
	rm -f *.o *.d backends/*.o backends/*.d verifier
