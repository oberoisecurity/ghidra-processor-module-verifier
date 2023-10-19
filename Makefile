CXX=g++
CXXFLAGS=-pipe -g -O2 -Wall -I $(GHIDRA_TRUNK)/Ghidra/Features/Decompiler/src/decompile/cpp/
DEPS = state.h
OBJ = main.o state.o sla_util.o backends/json.o backends/sla_emulator.o
LIBS=-lboost_system -lboost_filesystem -lboost_regex -lboost_program_options -L . $(GHIDRA_TRUNK)/Ghidra/Features/Decompiler/src/decompile/cpp/libsla.a

all: verifier

%.o: %.cpp $(DEPS)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(LIBS)

verifier: $(OBJ)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LIBS)

.PHONY: clean
clean:
	rm -f *.o backends/*.o verifier
