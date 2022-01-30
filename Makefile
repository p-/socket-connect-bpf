BINARY_NAME=socket-connect-bpf
 
all: build test
 
build:
	go generate
	GOOS=linux GOARCH=amd64 go build -o bin/amd64/${BINARY_NAME}
	GOOS=linux GOARCH=arm64 go build -o bin/arm64/${BINARY_NAME}
 
test:
	go test ./...

clean:
	go clean
	rm -f bpf_bpfel_*.go
	rm -f bin/amd64/${BINARY_NAME}
	rm -f bin/arm64/${BINARY_NAME}
