FROM golang:1.10.3
WORKDIR /go/src/app

RUN apt-get update
RUN apt-get install libudev-dev
RUN go get -t "github.com/jochenvg/go-udev"
RUN apt-get install -y libpcsclite-dev
RUN go get -t "github.com/ebfe/scard"
RUN apt-get install -y libgtk-3-dev
RUN go get -t "github.com/gotk3/gotk3/gtk"
RUN go get -t "golang.org/x/crypto/pbkdf2"
RUN apt-get install -y libusb-1.0-0-dev
RUN go get -t "github.com/google/gousb"
RUN go get -t "github.com/jessevdk/go-flags"
RUN go get -t "github.com/gotk3/gotk3/gdk"

COPY . .

RUN go build -ldflags="-s -w" -v ./...

RUN ls -lh app
