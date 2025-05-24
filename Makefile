
CXX = clang++
CXXFLAGS = -Wall -Wextra -fpic -fPIC -ggdb3 -Os -std=gnu++17 -shared -fno-stack-protector
LIBS = -lstdc++ -lpthread

all: gwhttplogger.so

gwhttplogger.so: gwhttplogger.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f gwhttplogger.so
