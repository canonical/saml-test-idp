FROM golang:latest as builder

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o samlidp samlidp.go

FROM scratch

COPY --from=builder /build/samlidp /bin/samlidp

CMD ["/bin/samlidp"]
