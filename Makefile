CXX ?= g++
CXXFLAGS ?= -std=c++23 -O2 -Wall -Wextra -Wpedantic -Werror

.PHONY: check test cpp-build cpp-run clean

check: test cpp-build

test:
	python3 -m unittest discover -s tests -p 'test_*.py'

cpp-build:
	mkdir -p build
	$(CXX) $(CXXFLAGS) cpp/telemetry_ring.cpp -lrt -lpthread -o build/telemetry_ring

cpp-run: cpp-build
	./build/telemetry_ring

clean:
	rm -rf build __pycache__ python/__pycache__ tests/__pycache__
