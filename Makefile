
CXXFLAGS = -Wall -Wextra -fpic -fPIC -ggdb3 -Os -std=c++17 -shared
LIBS = -lstdc++ -lpthread

all: gwhttplogger.so

gwhttplogger.so: gwhttplogger.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f gwhttplogger.so
