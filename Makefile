.PHONY: build up down test test-binaries

build:
	zig build

up:
	zig-out/bin/moxid &

down:
	pkill -x moxid

test:
	zig build test

test-binaries:
	zig build testbinaries
	sh test/test.sh zig-out/bin/zig_helloworld
	sh test/test.sh zig-out/bin/zig_pie
	sh test/test.sh zig-out/bin/zig_libc
	sh test/test.sh zig-out/bin/c_test
