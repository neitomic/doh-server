# show help if no command is specified: running only make
.DEFAULT_GOAL := help

help:
	@echo "Usage:"
	@echo "  make [target] [options]"
	@echo ""
	@echo "Targets:"
	@echo "  bench       - Run benchmarks (default: all record types)"
	@echo "  run         - Run the project using 'cargo run'"
	@echo "  test        - Run tests using 'cargo test'"
	@echo "  help        - Display this help message"
	@echo ""
	@echo "Benchmark options:"
	@echo "  RECORD_TYPE - Specific record type to benchmark (default: all types)"
	@echo "                Options: A, AAAA"
	@echo "  THREADS     - Number of threads to use (default: 4)"
	@echo "  CONNECTIONS - Number of connections to keep open (default: 10)"
	@echo "  DURATION    - Duration of the test, e.g., 30s, 1m, 2h (default: 30s)"
	@echo "  SERVER_URL  - URL of the DoH server (default: https://localhost/dns-query)"
	@echo ""
	@echo "Examples:"
	@echo "  make run                      # Run the project"
	@echo "  make test                     # Run tests"
	@echo "  make bench                    # Run all benchmarks with default settings"
	@echo "  make bench RECORD_TYPE=A      # Run benchmark for A records only"
	@echo "  make bench THREADS=8 CONNECTIONS=100 DURATION=1m  # Custom benchmark settings"


# target commands that to be run by make, not files
.PHONY: help run test bench

run-deps:
	@docker compose up -d

run:
	@cargo run 

test:
	@cargo test

# Default values
THREADS ?= 4
CONNECTIONS ?= 10 # # concurrent connections to maintain
DURATION ?= 30s
SERVER_URL ?= https://localhost/dns-query

RECORD_TYPES = A AAAA

bench: $(RECORD_TYPES)

# Target for each record type
$(RECORD_TYPES):
	@echo "Benchmarking $@ records"
	@wrk -t$(THREADS) -c$(CONNECTIONS) -d$(DURATION) -s benchmark/wrk-script.lua $(SERVER_URL) -- $@

