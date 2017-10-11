# godnscaptureclickhouse
[![Build Status](https://travis-ci.org/fdns/godnscaptureclickhouse.svg?branch=master)](https://travis-ci.org/fdns/godnscaptureclickhouse)

A implementation of the library https://github.com/fdns/godnscapture using ClickHouse

## Setting up ClickHouse

You must import the file tables.sql to your ClickHouse database manually. It will create the DNS_LOG table where the data is inserted, and different views with the aggregated data.
You can execute this using docker with the following command

```sh
cat tables.sql | docker run -i -a stdin --rm --net=host yandex/clickhouse-client --multiquery
```

## Example

To run the capturer on eth0

```sh
./gopassivednsclickhouse -serverName localserver -clickhouseAddress localhost:9000 -devName eth0
```

## Docker
You can run an example using docker-compose inside the docker folder. This contain godnscaptureclickhouse, clickhouse and grafana.
You will need to create the tables manually and upload the file `docker/grafana/panel.json` to grafana when creating a new panel.

lo is the default device listened, and you can change it in `docker/docker-compose.yml`
```sh
(cd docker && docker-compose up -d)
# Wait for clickhouse to start
cat tables.sql | docker run -i -a stdin --rm --net=host yandex/clickhouse-client --multiquery
```

## Arguments

|Argument|Description|
|--- | --- |
|devName|Device used to capture|
|pcapFile|Pcap filename to run|
|filter|BPF filter applied to the packet stream. Note that if port is selected, the packets will not be defragged.|
|port|Port selected to filter packets|
|gcTime|Time in seconds to garbage collect the tcp assembly and ipv4 defragmentation|
|clickhouseAddress|Address of the clickhouse database to save the results|
|clickhouseDelay|Number of seconds to batch the packets|
|serverName|Name of the server used to index the metrics|
|batchSize|Minimun capacity of the cache array used to send data to clickhouse. Set close to the queries per second received to prevent allocations|
|resultChannelSize|Size of the result processor channel size|
|packetHandlerChannelSize|Size of the packet handler channel|
|packetHandlers|Number of routines used to handle received packets|
|tcpHandlers|Number of routines used to handle tcp assembly|
|tcpAssemblyChannelSize|Size of the tcp assembler|
|tcpResultChannelSize|Size of the tcp result channel|
|defraggerChannelSize|Size of the channel to send packets to be defragged|
|defraggerChannelReturnSize|Size of the channel where the defragged packets are returned|
|cpuprofile|write cpu profile to file|
|memprofile|write memory profile to file|
|loggerFilename|Show the file name and number of the logged string|
|packetLimit|Limit of packets logged to clickhouse every iteration. Default 0 (disabled)|
