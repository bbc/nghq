# nghq

**nghq** is a HTTP framing layer built ontop of
[ngtcp2](https://github.com/ngtcp2/ngtcp2) and aims to provide support for the
HTTP/QUIC mapping for running HTTP over IETF QUIC.

**NOTE: NGHQ IN IT'S CURRENT FORM ONLY SUPPORTS [draft-pardue-quic-http-mcast-02](https://tools.ietf.org/html/draft-pardue-quic-http-mcast-02), UNTIL SUCH A TIME AS UNICAST HTTP/QUIC IS ADDED**

Currently, **nghq** only supports
[draft-ietf-quic-http-09](https://tools.ietf.org/html/draft-ietf-quic-http-09) 
as draft-09 is the last to still use
[HPACK](https://tools.ietf.org/html/rfc7541) for header compression. Later
versions of quic-http mandate the use of
[QPACK](https://github.com/quicwg/base-drafts/blob/master/draft-ietf-quic-qpack.md)
, however there is currently no readily available QPACK encoder and decoder. 
Until such time as this issue is resolved, then this library relies on the
HPACK encoder and decoder from
[nghttp2](https://nghttp2.org/documentation/tutorial-hpack.html).

## Getting Started

**nghq** is currently designed to be built against a version of ngtcp2 that has
quic-transport-draft-09 support. The specific commit that has been targetted is
[775c737](https://github.com/ngtcp2/ngtcp2/commit/775c7371d8f8edcfdad2d0aaf2ff6f8d4a956b4f).
In addition, the library also requires [nghttp2](https://nghttp2.org) version
v1.11.0 or above.

If you wish to build and run the examples, you will also need
[libev](http://software.schmorp.de/pkg/libev.html) version 4.0 or above.

The build system itself uses Automake. To build the software, do the following:

    $ ./bootstrap
    $ ./configure
    $ make

### Options

To enable some fairly verbose debugging output from the library, you can supply
the `--enable-debug` option to the configure script. This will write output
from both nghq **and** ngtcp2 to the command line when the library is run.
Debugging output is disabled by default.

To install the software, use `make install`. To change where **nghq** will be
installed, use the `PREFIX` variable as below:

    $ ./configure PREFIX=/home/roadrunner/nghq-target
    $ make install

### Running the examples

If you had **libev** installed when building, then the examples in the
`examples/` directory will be built. Currently, there is a simple multicast
sender and a multicast receiver application. Run them with `--help` to see the
available runtime options.

## Credits

## License

This software is licensed under an MIT License. See the COPYING file for more.

## Contributing

## Authors

This software was written by [Sam Hurst](https://github.com/samhurst) with
additional contributions by [David Waring](https://github.com/davidjwbbc).

## Copyright

Copyright (c) 2018 British Broadcasting Corporation

