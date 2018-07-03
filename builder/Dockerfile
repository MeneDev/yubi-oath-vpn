FROM circleci/golang:1.10.3

RUN sudo apt-get update && sudo apt-get install -y \
    libgtk-3-dev \
    libpcsclite-dev \
    libudev-dev \
    libusb-1.0-0-dev \
&& sudo rm -rf /var/lib/apt/lists/*

RUN go get -u github.com/tcnksm/ghr \
    && go get -u github.com/stevenmatthewt/semantics

RUN curl -L -s https://github.com/golang/dep/releases/download/v0.4.1/dep-linux-amd64 -o /go/bin/dep \
    && chmod +x /go/bin/dep
