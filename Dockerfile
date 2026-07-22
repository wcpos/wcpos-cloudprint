# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /wcpos-cloudprint ./cmd/wcpos-cloudprint

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /wcpos-cloudprint /wcpos-cloudprint
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/wcpos-cloudprint"]
