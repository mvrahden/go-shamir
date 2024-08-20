all: test

.PHONY: all

dep:
	go mod download
	go mod verify

build: dep
	go build -o bin/shamir cli/main.go

.PHONY: build

test: build
	./tests/shamir

.PHONY: test
