FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/samma-mcp ./cmd/samma-mcp

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 samma
COPY --from=build /out/samma-mcp /usr/local/bin/samma-mcp
USER 10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/samma-mcp"]
