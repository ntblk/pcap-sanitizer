#!/usr/bin/env node

const program = require('commander');
const convert = require('./sanitize');
const ipaddr = require('ipaddr.js');
const execa = require('execa');
const fs = require('fs');

function collect(val, memo) {
  val = ipaddr.process(val);
  memo.push(val);
  return memo;
}

program
//  .version('0.0.0')
  .option('-r, --redact [ip]', 'IP, CIDR or subnet to redact', collect, [])
  .option('-a, --append', 'Append to existing pcap if [file] exists')
  .option('-o, --out [file]', 'Specify a single output file', '-')
  .parse(process.argv);

async function run () {
  var opts = {};
  opts.private_ranges = program.redact;
  //console.log(opts);
  //return;
  var files = program.args;

  // `${capfile}-b.json.pcap`

  var writeStream;

  if (program.out !== undefined && program.out !== '-')
    writeStream = fs.createWriteStream(program.out);
  else if (!process.stdout.isTTY)
    writeStream = process.stdout;
  else {
    console.error('no output file given');
    process.exit(1);
  }

  files.forEach(f => sani(f, writeStream, opts));
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
