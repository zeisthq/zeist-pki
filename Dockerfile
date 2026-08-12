# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.26.4 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=true -ldflags="-s -w" \
      -o /out/zeist-pki ./cmd/zeist-pki

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build --chown=nonroot:nonroot /out/zeist-pki /usr/local/bin/zeist-pki
COPY --from=build --chown=nonroot:nonroot /src/LICENSE /licenses/LICENSE

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/zeist-pki"]
