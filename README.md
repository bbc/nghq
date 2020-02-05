# nghq

**nghq** is a HTTP framing layer that aims to provide support for the
HTTP/QUIC mapping for running HTTP over IETF QUIC.

The **nghq** API is modelled after that of
[nghttp2](https://nghttp2.org/documentation/). The application owns the
communicating socket and feeds data into the library via a series of calls.
The application is expected to act on callbacks from the library. There are a
couple of important points to note:

* **nghq** does not own the socket. The application is expected to read data
from the socket and provide it to the library. When the library has some data
to send, it will call back into the application with the data to be sent on the
application's socket.
* **nghq** does not do any encryption or decryption of the packets received.
It is up to the application to manage the TLS context. The encrypt and decrypt
callbacks will be fired when the library needs encryption or decryption to be
done.

![nghq diagram](docs/nghq-libs-web.png)

The public API is documented [here](docs/public-api.md). In addition, the
library's public header file [nghq.h](include/nghq/nghq.h) has comment blocks
for every function and callback listed above it which also serve as
documentation.

Some helpful sequence diagrams, showing the expected interaction between a
client/server application and **nghq** can be found
[here](docs/sequence-diagrams.md).

## Caveats

**NOTE: In its current form, nghq implements only the parts of the QUIC and HTTP3 specifications required by [draft-pardue-quic-http-mcast-05](https://tools.ietf.org/html/draft-pardue-quic-http-mcast-05)**.

In particular, it only supports [draft-ietf-quic-http-22](https://tools.ietf.org/html/draft-ietf-quic-http-22).

## Getting Started

If you wish to build and run the examples, you will also need
[libev](http://software.schmorp.de/pkg/libev.html) version 4.0 or above.

**nghq** uses the [ls-qpack](https://github.com/litespeedtech/ls-qpack) library to perform QPACK header compression and decompression routines. The ls-qpack library is included as a linked git submodule, which should be initialised and updated as part of the bootstrap script.

The build system itself uses Automake. To build the software, do the following:

    $ ./bootstrap
    $ ./configure
    $ make

### Options

To enable some fairly verbose debugging output from the library, you can supply
the `--enable-debug` option to the configure script. This will write output
from nghq to the command line when the library is run.
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

If you have a feature request or want to report a bug, we'd be happy to hear
from you. Please either raise an issue, or fork the project and send us a pull
request.

## Authors

This software was written by [Sam Hurst](https://github.com/samhurst) with
additional contributions by [David Waring](https://github.com/davidjwbbc).

## Copyright

Copyright (c) 2020 British Broadcasting Corporation

