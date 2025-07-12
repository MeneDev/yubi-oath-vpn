FROM cimg/go:1.24.5

RUN sudo apt-get update && sudo apt-get install -y \
    libgtk-3-dev \
    libpcsclite-dev \
    libudev-dev \
    libusb-1.0-0-dev \
&& sudo rm -rf /var/lib/apt/lists/*

RUN go install github.com/tcnksm/ghr@v0.17.0 
RUN go install github.com/stevenmatthewt/semantics@v2.0.4
