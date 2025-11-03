go build -o build/stringx-unix-x86 -ldflags="-s -w" .
GOOS=darwin GOARCH=arm64 go build -o build/stringx-darwin-arm64 -ldflags="-s -w" .
GOOS=windows GOARCH=amd64 go build -o build/stringx-windows-x86.exe -ldflags="-s -w" .
GOOS=linux GOARCH=arm64 go build -o build/stringx-linux-arm64 -ldflags="-s -w" .
GOOS=linux GOARCH=386 go build -o build/stringx-linux-386 -ldflags="-s -w" .
GOOS=freebsd GOARCH=amd64 go build -o build/stringx-freebsd-x86 -ldflags="-s -w" .