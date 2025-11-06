rm -rf build

go build -o build/stringx-linux-x86-amd64 -ldflags="-s -w" src/main.go
GOOS=darwin GOARCH=arm64 go build -o build/stringx-darwin-arm64 -ldflags="-s -w" src/main.go
GOOS=windows GOARCH=amd64 go build -o build/stringx-windows-x86.exe -ldflags="-s -w" src/main.go
GOOS=linux GOARCH=arm64 go build -o build/stringx-linux-arm64 -ldflags="-s -w" src/main.go
GOOS=linux GOARCH=386 go build -o build/stringx-linux-386 -ldflags="-s -w" src/main.go
GOOS=freebsd GOARCH=amd64 go build -o build/stringx-freebsd-x86-amd64 -ldflags="-s -w" src/main.go

for file in $(ls build | cat); do
    sha256sum build/$file | awk '{split($2,a,"/"); print $1, a[length(a)]}' >> build/checksums.txt
done