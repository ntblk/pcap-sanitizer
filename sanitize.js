const assert = require('assert');
const ipaddr = require('ipaddr.js');
const braces = require('braces');
const _ = require('lodash');
const JSONStream = require('JSONStream');
const es = require('event-stream');

const {pcap_tables, pcap_hdr_t, pcaprec_hdr_t} = require('./pcap');

const seedrandom = require('seedrandom');
var rng = seedrandom('misc');

function generateMacAddr(prefix) {
  var mac = prefix || '54:52:00';

  for (var i = 0; i < 6; i++) {
    if (i%2 === 0) mac += ':';
    mac += Math.floor(rng()*16).toString(16);
  }

  return mac;
};

function ipToInt(ipv) {
  return Buffer.from(ipv.octets).readUIntBE(0, 4);
}

function intToIp(ip) {
  //return ipaddr.fromByteArray(Buffer.alloc(4).writeUIntBE(ip, 0, 4));
  var b = Buffer.alloc(4);
  b.writeUIntBE(ip, 0, 4);
  return ipaddr.fromByteArray(b);
}

var ipv4base = ipaddr.parse('10.0.0.1');
var ipv4offs = 0;

function generateIPAddr() {
  var mac = '';

  for (var i = 0; i < 8; i++) {
    mac += Math.floor(Math.random()*16).toString(16);
  }

  return mac;
};

function checksum (buffer) {
  const wordSize = 2;
  var sum = 0;
  for (var i = 0; i < buffer.length; i += wordSize)
    sum += buffer.readUIntBE(i, Math.min(wordSize, buffer.length-i));
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  sum = ~sum;
  return (new Uint16Array([sum]))[0];
}

function mutate(s) {
    return function splice() {
        var a = s.split('');
        Array.prototype.splice.apply(a, arguments);
        return a.join('');
    };
}


var ethMap = new Map();

function dumpMap (map) {
  for (var [key, value] of map) {
    console.log(key + ' = ' + value);
  }
}

function parseField (field, parentField) {
  assert(field);
  var p = {
    hex: field[0],
    position: field[1], //*2
    length: field[2], //*2
    bitmask: field[3],
    type: field[4],
  };

  if (pcap_tables.ftypes)
    p.type_info = pcap_tables.ftypes[p.type];

  if (p.hex != null) {
    p.hex_orig = p.hex;

    // FIXME: Why is this needed?
    let needed = p.hex.length % Math.max(2, p.length);
    if (needed)
      p.needed = needed;
    while (needed--)
      p.hex = '0' + p.hex;

    p.buffer_inline = Buffer.from(p.hex, 'hex');
  }

  if (parentField)
    p.buffer = parentField.buffer.slice(p.position, p.position + p.length);
  else {
    p.buffer = p.buffer_inline;
  }

  if (p.bitmask) {
    console.error('TODO: bitmask');
    console.error(p);
    //return p;
  }

  var m;

  if (['FT_IPv4', 'FT_IPv6'].includes(p.type_info.name)) {
    p.addr = ipaddr.fromByteArray(p.buffer);
    p.text = p.addr.toString();

    p.get = () => {
      return ipaddr.fromByteArray(p.buffer);
    };

    p.set = (value) => {
      Buffer.from(value.octets).copy(p.buffer, 0);
    };

    Object.defineProperty(p, 'ip_addr', {
      get() { return ipaddr.fromByteArray(this.buffer); },
      set(value) { Buffer.from(value.octets).copy(this.buffer, 0); },
      enumerable: true,
      configurable: false,
    });
  //} else if (['FT_STRING'].includes(p.type_info.name)) {
  //  p.text = p.buffer.toString('ascii');
  } else if (m = p.type_info.name.match(/^FT_(U)?INT(\d+)$/)) {
    var signed = !m[1];
    var byteLength = parseInt(m[2], 10) / 8;
    // TODO: hex is sometimes shorter than what we need, so adjust - but why?
    byteLength = Math.min(byteLength, p.buffer.length);

    Object.defineProperty(p, 'number', {
      get() {
        return signed ? p.buffer.readIntBE(0, byteLength) : p.buffer.readUIntBE(0, byteLength);
      },
      set(value) {
        if (signed)
          p.buffer.writeIntBE(value, 0, byteLength);
        else
          p.buffer.writeUIntBE(value, 0, byteLength);
      },
      enumerable: true,
      configurable: false,
    });
  }

  return p;
}

function dumpFields (a) {
  for (let k in a) {
    if (!k.endsWith('_raw'))
      continue;
    console.log({k, v: parseField(a[k])})
  }
}

function streamMap (inStream, glob, cb) {
  return inStream
  .pipe(JSONStream.parse('*'))
  .pipe(es.mapSync(cb));
}

async function convert (inStream, writeStream, opts) {
  write_pcap_header(writeStream);

  //var pcap = fs.readFileSync(`${capfile}.json`, 'utf8');
  //pcap = JSON.parse(pcap);
  //fs.writeFileSync(`${capfile}-a.json`, JSON.stringify(pcap, null, 2), 'utf8');

  var og_ip = _.memoize(hex => {
    var arr = ipv4base.toByteArray();
    arr[arr.length-1] += ipv4offs++;
    return ipaddr.fromByteArray(arr);
  });

  var rangeList = {
    redact: opts.private_ranges,
  };

  // FT_IPv4
  var genIP = (hex, field) => {
    var ipa = field.ip_addr;

    if (ipaddr.subnetMatch(ipa, rangeList, 'none') === 'redact' ||
        (opts.private && ['private'].includes(ipa.range()))) {
      field.ip_addr = og_ip(hex);
    }

    return hex;
  };

  var genMACaddr = orig => generateMacAddr().replace(/:/g,'').toLowerCase();
  genMACaddr = _.memoize(genMACaddr);

  // FT_ETHER
  var genMAC = (hex, field) => {
    if (opts.mac)
      Buffer.from(genMACaddr(hex), 'hex').copy(field.buffer);
    return hex;
  };

  var g_ip = genIP;
  var g_mac = genMAC;

  var caches = {
    ip: g_ip.cache,
    mac: g_mac.cache,
  };


  await streamMap(inStream, '*', frame => {
    var res = convertFrame(frame._source.layers);
    write_pcap_frame(writeStream, res);
  });
  //writeStream.end();


  function convertFrame (layers) {
    //const layers = frame._source.layers;

/*
    dumpFields(frame._source.layers.eth);
    dumpFields(frame._source.layers.ip);
    dumpFields(frame._source.layers.ipv6);
    dumpFields(frame._source.layers.tcp);
    dumpFields(frame._source.layers.udp);
    dumpFields(frame._source.layers.arp);
*/

    var a, b;

    var frameField = parseField(layers.frame_raw);

/*
    if (frame._source.layers.ip) {
      var hdr = parseField(frame._source.layers.ip_raw, frameField);
      var fld = parseField(frame._source.layers.ip['ip.checksum_raw'], frameField);
      //var osum = fld.number;
      fld.number = 0;
      fld.number = checksum(hdr.buffer);
    }
    */
    if (0)
    if (layers.tcp) {
      var prt = parseField(layers.tcp['tcp.dstport_raw'], frameField);
      prt.prtname = _.find(pcap_tables.decodes['tcp.port'], v => v.selector === prt.number);
      console.log(prt.number);
      console.log(prt);
    }

    a = layers.ip;
    b = a;
    remap("ip.{src,dst}", g_ip);

    a = layers.arp;
    //b = a;
    b = layers.arp = {};
    remap("arp.{src,dst}.hw_mac", g_mac);
    remap("arp.{src,dst}.proto_{ipv4,ipv6}", g_ip);


    a = layers.ipv6;
    //b = a;
    b = layers.ipv6 = {};
    remap("ipv6.{src,dst}", g_ip);

    a = layers.eth;
    //b = a;
    b = layers.eth = {};
    remap("eth.{src,dst}", g_mac);

    fixChecksums(layers, frameField);

    function remap (fieldName, updater) {
      return braces.expand(fieldName).map(v => remapField(v, updater));
    }

    // TODO: updater is like lodash's _.update() - just use that?
    function remapField(fieldName, updater) {
      let input = a;
      let output = b;

      if (input === undefined)
        return;

      fieldName += '_raw';
      var field = input[fieldName];

      if (field === undefined)
        return;

      var oldaddr = field[0];
      var newaddr;

      var finfo = parseField(field, frameField);
      newaddr = updater(oldaddr, finfo);

      if (oldaddr === newaddr)
        return;

      field[0] = newaddr;
      output[fieldName] = field;
    }

    return {layers, data: frameField.buffer};
  }
}

const NetChecksum = require('netchecksum');

function fixChecksums (layers, frameField) {
  // update ipv4 checksum
  if (layers.ip) {
    var hdr = parseField(layers.ip_raw, frameField);
    var fld = parseField(layers.ip['ip.checksum_raw'], frameField);
    //var osum = fld.number;
    fld.number = 0;
    //fld.number = checksum(hdr.buffer);
    fld.number = NetChecksum.raw(hdr.buffer);
  }

  if (layers.udp && layers.udp['udp.checksum_raw']) {
    var fld = parseField(layers.udp['udp.checksum_raw'], frameField);
    var hdr = parseField(layers.udp_raw, frameField);

    function getBuf(layer, name) {
      return parseField(layers[layer][name + '_raw'], frameField).buffer;
    }

    var pseudovec = [
      getBuf('ip', ['ip.src']),
      getBuf('ip', ['ip.dst']),
      Buffer.from([0, 17]), // udp
      getBuf('udp', ['udp.length']),
      getBuf('udp', ['udp.srcport']),
      getBuf('udp', ['udp.dstport']),
      getBuf('udp', ['udp.length']),
      Buffer.from([0, 0]),
      frameField.buffer.slice(hdr.position + hdr.length),
    ];

    const pseudo = Buffer.concat(pseudovec);
    fld.number = NetChecksum.raw(pseudo);
  }
}

async function write_pcap_header (writeStream) {
  var hdr = {};
  hdr.magic_number = 0xa1b2c3d4;
  hdr.version_major = 2;
  hdr.version_minor = 4;
  hdr.network = 1; // ethernet
  hdr.snaplen = 65535;
  writeStream.write(pcap_hdr_t.write(hdr));
}

async function write_pcap_frame (writeStream, frame) {
  var ts = [0,0];

  // Unfortunately not present in jsonraw output
  let epoch = frame.layers.frame['frame.time_epoch'];
  if (epoch)
    ts = epoch.split('.').map(v => parseInt(v, 10));

  var rec_hdr = {
    ts_sec: ts[0],
    ts_usec: ts[1]/1000,
    incl_len: frame.data.length, // TODO: snaplen?
    orig_len: frame.data.length,
  };

  writeStream.write(pcaprec_hdr_t.write(rec_hdr));
  writeStream.write(frame.data);
}

module.exports = convert;
