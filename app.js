#!/usr/bin/env node

const program = require('commander');
const convert = require('./sanitize');
const ipaddr = require('ipaddr.js');
const execa = require('execa');
const fs = require('fs');

function collect(val, memo) {
  if (ipaddr.isValid(val)) {
    val = ipaddr.parse(val);
    val = [val, val.kind() == 'ipv6' ? 128 : 32];
  } else {
    val = ipaddr.parseCIDR(val);
  }
  memo.push(val);
  return memo;
}

program
//  .version('0.0.0')
  .option('-r, --redact [ip]', 'IP, CIDR or subnet to redact', collect, [])
  .option('-p, --redact-private', 'redact all subnets assigned for private use')
  .option('-m, --redact-mac', 'randomize ethernet hardware MAC addresses')
  .option('-a, --append', 'Append to existing pcap if [file] exists')
  .option('-o, --out [file]', 'Specify a single output file', '-')
  .parse(process.argv);

async function run () {
  var opts = {};
  opts.private_ranges = program.redact;
  opts.private = !!program.redactPrivate;
  opts.mac = !!program.redactMac;
  var files = program.args;

  var writeStream;
  if (program.out !== undefined && program.out !== '-')
    writeStream = fs.createWriteStream(program.out);
  else if (!process.stdout.isTTY)
    writeStream = process.stdout;
  else {
    console.error('no output file given');
    process.exit(1);
  }

  for (let f of files)
    await sani(f, writeStream, opts);
  //files.forEach(f => sani(f, writeStream, opts));
  //writeStream.end();
}

async function sani (capfile, writeStream, opts = {}) {
  // jsonraw has no timestamps
  //var proc = execa.shell(`tshark -r ${capfile} -T jsonraw`);
  var proc = execa.shell(`tshark -r ${capfile} -T json -x`);
  // FIXME: This doesn't wait
  await convert(proc.stdout, writeStream, opts);
}

run();
