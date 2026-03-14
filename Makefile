.PHONY: all
all: test

.PHONY: clean
clean:
	@rm test/a.out
	done

.PHONY: daemon
daemon:
	cargo run --bin=moxid

.PHONY: start
start:
	gcc -g -O0 -o test/a.out test/test.c
	cargo run --bin=moxi_start -- test/a.out
