# godnscapture
[![Build Status](https://travis-ci.org/fdns/godnscapture.svg?branch=codecov)](https://travis-ci.org/fdns/godnscapture)
[![codecov](https://codecov.io/gh/fdns/godnscapture/branch/master/graph/badge.svg)](https://codecov.io/gh/fdns/godnscapture)

Go library to capture DNS packets, based on https://github.com/Phillipmartin/gopassivedns. This library doesn't associate requests and responces of dns packets, and its used for raw logging.

This library support IPv4 and IPv6 protocols (+fragmented), using TCP or UDP.

## Updating dependencies
To update dependencies, use the official dep manager at https://github.com/golang/dep and run
```sh
$ dep ensure -update
```

