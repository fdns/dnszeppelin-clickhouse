# DnsZeppelin
[![Build Status](https://travis-ci.org/fdns/dnszeppelin.svg?branch=codecov)](https://travis-ci.org/fdns/dnszeppelin)
[![codecov](https://codecov.io/gh/fdns/dnszeppelin/branch/master/graph/badge.svg)](https://codecov.io/gh/fdns/dnszeppelin)

Go library to capture DNS packets, based on https://github.com/Phillipmartin/gopassivedns. This library doesn't associate requests and responses of dns packets, and its used for raw logging.

This library support IPv4 and IPv6 protocols (plus fragmented), using TCP or UDP.

There is one implementation storing the data in a ClickHouse database at https://github.com/fdns/dnszeppelin-clickhouse

## Updating dependencies
To update dependencies, use the official dep manager at https://github.com/golang/dep and run
```sh
$ dep ensure -update
```

