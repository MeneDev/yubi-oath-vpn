FROM menedev/yubi-oath-vpn-builder:latest

RUN mkdir -p /go/src/github.com/MeneDev/yubi-oath-vpn
WORKDIR /go/src/github.com/MeneDev/yubi-oath-vpn
COPY . .

ENV GOCACHE=/tmp/go/cache

RUN mkdir -p $GOCACHE

RUN find $GOCACHE
RUN /go/bin/dep ensure
RUN find $GOCACHE
RUN find vendor/ -maxdepth 3 -mindepth 3 -exec bash -c 'cd $0 && go build  ./...' {} \;
RUN find $GOCACHE

RUN go build -ldflags="-s -w" -v ./...


#RUN find

