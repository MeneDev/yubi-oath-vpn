# requires buildkit for caching; run: DOCKER_BUILDKIT=1 docker build -t yubi-oath-vpn .

FROM yubi-oath-vpn-builder:latest

# download dependencies
RUN mkdir -p /go/src/github.com/MeneDev/yubi-oath-vpn
WORKDIR /go/src/github.com/MeneDev/yubi-oath-vpn
COPY go.* ./
RUN go mod download

# build project
COPY . ./
RUN --mount=type=cache,target=/go/.cache CIRCLE_BUILD_NUM=build123 CIRCLE_SHA1=aabbccddeeff go build -ldflags="-s -w -X \"main.Version=${tag:-not a release}\" -X \"main.BuildDate=$(date --utc)\" -X \"main.BuildNumber=$CIRCLE_BUILD_NUM\" -X \"main.BuildCommit=$CIRCLE_SHA1\"" -o yubi-oath-vpn-linux_amd64 ./cmd/yubi-oath-vpn/
ENTRYPOINT ["./yubi-oath-vpn-linux_amd64"]