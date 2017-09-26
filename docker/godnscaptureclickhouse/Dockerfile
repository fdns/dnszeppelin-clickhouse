FROM golang:1.8

RUN apt-get update && apt-get install -y libpcap0.8-dev

WORKDIR /go/src/app
COPY . .

RUN go-wrapper download
RUN go-wrapper install

ARG DEV=lo
ENV DEV=lo

CMD ["sh", "-c", "go-wrapper run -devName=$DEV -clickhouseAddress clickhouse:9000"]
