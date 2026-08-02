FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.buildVersion=$VERSION" -o /relay .

FROM scratch
COPY --from=build /relay /relay
ENTRYPOINT ["/relay"]