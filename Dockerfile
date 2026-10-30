# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build

ENV GOTOOLCHAIN=local

WORKDIR /src

COPY go.mod go.sum ./
RUN test "$(go env GOVERSION)" = go1.26.10 && go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=true -ldflags="-s -w" \
      -o /out/zeist-pki ./cmd/zeist-pki

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

COPY --from=build --chown=nonroot:nonroot /out/zeist-pki /usr/local/bin/zeist-pki
COPY --from=build --chown=nonroot:nonroot /src/LICENSE /licenses/LICENSE

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/zeist-pki"]
