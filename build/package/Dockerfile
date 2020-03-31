FROM golang:1.13.8-buster
LABEL maintainer="Siddhartha Basu <siddhartha-basu@northwestern.edu>"
LABEL maintainer="Eric Hartline <eric.hartline@northwestern.edu>"
ENV GOPROXY https://proxy.golang.org
RUN mkdir -p /modware-auth
WORKDIR /modware-auth
COPY go.mod ./
COPY go.sum ./
RUN go mod download
ADD cmd cmd
ADD internal internal
RUN go build -o app cmd/modware-auth/main.go

FROM gcr.io/distroless/static
COPY --from=0 /modware-auth/app /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/app"]