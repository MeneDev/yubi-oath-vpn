FROM menedev/yubi-oath-vpn-builder:latest

ENV GOCACHE=/tmp/go/cache
RUN mkdir -p $GOCACHE

# build dependencies
RUN mkdir -p /go/src/github.com/MeneDev/yubi-oath-vpn
WORKDIR /go/src/github.com/MeneDev/yubi-oath-vpn
COPY Gopkg.* ./
RUN /go/bin/dep ensure --vendor-only
RUN find vendor/ -maxdepth 3 -mindepth 3 -exec bash -c 'cd $0 && go build -v ./...' {} \;

# build project
COPY *.go ./
RUN gox -ldflags="-s -w" -os="linux" -arch="amd64" -output "release/yubi-oath-vpn-{{.OS}}_{{.Arch}}"

