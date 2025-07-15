FROM cimg/go:1.24.5

RUN sudo apt-get update && sudo apt-get install -y \
    libgtk-3-dev \
    libpcsclite-dev \
    libudev-dev \
    libusb-1.0-0-dev \
    mingw-w64 \
    mingw-w64-common \
    mingw-w64-tools \
    mingw-w64-dev \
    gcc-mingw-w64-x86-64 \
    gettext \
&& sudo rm -rf /var/lib/apt/lists/*

ENV GOPATH=/go
ENV GOCACHE=/go/.cache
ENV PATH="$PATH:$GOPATH/bin"

# hack, but currently don't bother how to properly setup go in current version
RUN sudo mkdir /go
RUN sudo chmod a+rwx /go

RUN go install github.com/tcnksm/ghr@v0.17.0 
RUN go install github.com/stevenmatthewt/semantics@v2.0.4

# CGO_LDFLAGS_ALLOW='.*' CGO_CFLAGS_ALLOW='.*' CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ CGO_ENABLED=1 GOOS=windows GOARCH=amd64 PKG_CONFIG_PATH=/usr/x86_64-w64-mingw32/sys-root/mingw/lib/pkgconfig go build -v github.com/MeneDev/yubi-oath-vpn/cmd/yubi-oath-vpn
# cp /usr/x86_64-w64-mingw32/sys-root/mingw/bin/{libatk-1.0-0.dll,libbz2-1.dll,libcairo-2.dll,libcairo-gobject-2.dll,libepoxy-0.dll,libexpat-1.dll,libffi-6.dll,libfontconfig-1.dll,libfreetype-6.dll,libgcc_s_seh-1.dll,libgdk-3-0.dll,libgdk_pixbuf-2.0-0.dll,libgio-2.0-0.dll,libgit2.dll,libglib-2.0-0.dll,libgmodule-2.0-0.dll,libgobject-2.0-0.dll,libgraphite2.dll,libgtk-3-0.dll,libharfbuzz-0.dll,libiconv-2.dll,libintl-8.dll,libjasper-1.dll,libjpeg-8.dll,libpango-1.0-0.dll,libpangocairo-1.0-0.dll,libpangoft2-1.0-0.dll,libpangowin32-1.0-0.dll,libpcre-1.dll,libpixman-1-0.dll,libpng16-16.dll,libstdc++-6.dll,libwinpthread-1.dll,zlib1.dll} /go/src/github.com/MeneDev/yubi-oath-vpn/release
