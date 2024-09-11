all: test

.PHONY: all

dep:
	go mod download
	go mod verify

build: dep
	go build -a -ldflags="-w -s" -o ./bin/shamir ./cmd/shamir/.

.PHONY: build

test: build
	./tests/shamir

.PHONY: test
