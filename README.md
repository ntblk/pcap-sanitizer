## pcap-sanitizer

<img src="https://netblocks.org/images/netblocks-pcap-sticker.png" width="200px" align="right" />

``pcap-sanitizer`` is a code module and utility that removes private information from packet capture files.

It can remap IPv4, IPv6, TCP, UDP, ARP and ethernet frame hardware addresses using a deterministic address generation algorithm.

[![NPM Version][npm-image]][npm-url]

## Synopsis

<img src="https://netblocks.org/files/netblocks-logo.png" width="200px" align="left" alt="NetBlocks" style="margin: 0.5em;" />

Packet captures play an important role in the diagnosis of internet disruptions, but by design they take a full collection of network traffic that can introduce risk and harm privacy.

``pcap-sanitizer`` makes it possible to remove data from packet captures that is not vital to the task at hand. This is done using a variety of techniques:

* Remapping IP addresses
* Generating pseudorandom hardware addresses
* Optionally removing data payloads
* Rebuilding checksums to preserve integrity
* Providing an audit trail of modifications

This package is maintained as part of the the
[NetBlocks.org](https://netblocks.org) network observation framework.

## Features

* IPv4 and IPv6 support as well as a selection of higher layer protocols
* Checksum validation and generation for:
  - IPv4
  - UDP
* Stream-oriented modular programming interface
* A handy commandline tool is also provided for interactive work
* Reactive API: updates are immediately reflected in binary output

## Usage guide

### Command-line tool

A command-line utility is included that can be used for testing or to seed and exist a deployed cache instance.

```bash
$ npm install -g pcap-sanitizer
```

After installing globally the utility should be available on your PATH:

```
$ pcap-sanitizer --help
Usage: pcap-sanitizer [options]

Options:

  -r, --redact [ip]     IP, CIDR or subnet to redact (default: )
  -p, --redact-private  redact all subnets assigned for private use
  -m, --redact-mac      randomize ethernet hardware MAC addresses
  -a, --append          Append to existing pcap if [file] exists
  -o, --out [file]      Specify a single output file (default: -)
  -h, --help            output usage information

The NetBlocks Project <https://netblocks.org>
```

### Programming interface

#### Installation

```bash
$ npm install pcap-sanitizer
```

`pcap-sanitizer` exposes a stream-based asynchronous programming interface that processes packets on the fly.

```js
const sanitize = require('pcap-sanitizer');

sanitize(inStream, outStream, opts);
...
```

Tests and sources are currently the best place to look for usage examples.

## Status

`pcap-sanitizer` is in use on probe equipment and also finds use as a commandline tool in research work. Although core functionality is considered reliable, it has not yet been tested with arbitrary inputs or deployed in high-bandwidth scenarios. The code is structured with the goal of supporting client-side operation.

[npm-image]: https://img.shields.io/npm/v/pcap-sanitizer.svg?style=flat-square
[npm-url]: https://npmjs.org/package/pcap-sanitizer
[npm-downloads]: https://img.shields.io/npm/dm/pcap-sanitizer.svg?style=flat-square
