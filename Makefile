test:
	go test -v ./...

build: test
	go build -o ./bin/app ./cmd/main/main.go

run: build test
	./bin/app

clean:
	rm -rf ./bin
