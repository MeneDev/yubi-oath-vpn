FROM fedora:36

RUN dnf install -y \
        findutils \
        git \
        golang \
        gtk3-devel \
        libudev-devel \
        libusbx-devel \
        mingw32-gcc \
        mingw64-gcc \
        mingw32-gcc-c++ \
        mingw32-glib2 \
        mingw32-gtk3 \
        mingw32-libusbx \
        mingw64-gcc-c++ \
        mingw64-glib2 \
        mingw64-gtk3 \
        mingw64-libusbx \
        pcsc-lite-devel \
        zip \
        && \
        dnf clean all

ENV GOPATH /go
ENV GOCACHE /go/.cache
ENV PATH "$PATH:$GOPATH/bin"

RUN go install github.com/tcnksm/ghr@v0.15.0 
RUN go install github.com/stevenmatthewt/semantics@latest

# CGO_LDFLAGS_ALLOW='.*' CGO_CFLAGS_ALLOW='.*' CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ CGO_ENABLED=1 GOOS=windows GOARCH=amd64 PKG_CONFIG_PATH=/usr/x86_64-w64-mingw32/sys-root/mingw/lib/pkgconfig go build -v github.com/MeneDev/yubi-oath-vpn/cmd/yubi-oath-vpn
# cp /usr/x86_64-w64-mingw32/sys-root/mingw/bin/{libatk-1.0-0.dll,libbz2-1.dll,libcairo-2.dll,libcairo-gobject-2.dll,libepoxy-0.dll,libexpat-1.dll,libffi-6.dll,libfontconfig-1.dll,libfreetype-6.dll,libgcc_s_seh-1.dll,libgdk-3-0.dll,libgdk_pixbuf-2.0-0.dll,libgio-2.0-0.dll,libgit2.dll,libglib-2.0-0.dll,libgmodule-2.0-0.dll,libgobject-2.0-0.dll,libgraphite2.dll,libgtk-3-0.dll,libharfbuzz-0.dll,libiconv-2.dll,libintl-8.dll,libjasper-1.dll,libjpeg-8.dll,libpango-1.0-0.dll,libpangocairo-1.0-0.dll,libpangoft2-1.0-0.dll,libpangowin32-1.0-0.dll,libpcre-1.dll,libpixman-1-0.dll,libpng16-16.dll,libstdc++-6.dll,libwinpthread-1.dll,zlib1.dll} /go/src/github.com/MeneDev/yubi-oath-vpn/release
