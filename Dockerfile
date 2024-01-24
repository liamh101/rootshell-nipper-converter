FROM golang:1.21

ENV GO111MODULE=on

ADD . /usr/local/go/src/prismNipper3
WORKDIR /usr/local/go/src/prismNipper3
RUN go mod download && go mod verify 
RUN go build -v

CMD ["app"]