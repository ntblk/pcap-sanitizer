//@flow

const assert = require('assert');
const fs = require('fs');
const ipaddr = require('ipaddr.js');
const execa = require('execa');
const braces = require('braces');

var tables = require('./tables.json');

const _ = require('lodash');

function generateMacAddr(prefix) {
  var mac = prefix || '54:52:00';

  for (var i = 0; i < 6; i++) {
    if (i%2 === 0) mac += ':';
    mac += Math.floor(Math.random()*16).toString(16);
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

//var ipv4base = ipToInt(ipaddr.parse('10.0.0.1'));
var ipv4base = ipaddr.parse('10.0.0.1');
var ipv4offs = 0;

function generateIPAddr() {
  var mac = '';

  for (var i = 0; i < 8; i++) {
    mac += Math.floor(Math.random()*16).toString(16);
  }

  return mac;
};

function checksum(array) {
 var buffer = array;//Buffer.from(array);
 var sum = 0;
 for (var i=0; i<buffer.length-1; i=i+2) {
 sum += buffer.readUIntBE(i, 2);
 }
 sum = (sum >> 16) + (sum & 0xFFFF);
 sum += (sum >> 16);
 sum = ~sum;
 //return unsigned
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

  if (tables.ftypes)
    p.type_info = tables.ftypes[p.type];

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
    //console.log(p);
    p.addr = ipaddr.fromByteArray(p.buffer);
    p.text = p.addr.toString();

    p.get = () => {
      return ipaddr.fromByteArray(p.buffer);
    };

    p.set = (value) => {
      //Buffer.from(value.toByteArray()).copy(p.buffer, 0);
      Buffer.from(value.octets).copy(p.buffer, 0);
    };

    Object.defineProperty(p, 'ip_addr', {
      // Using shorthand method names (ES2015 feature).
      // This is equivalent to:
      // get: function() { return bValue; },
      // set: function(newValue) { bValue = newValue; },
      get() { return ipaddr.fromByteArray(this.buffer); },
      set(value) { Buffer.from(value.octets).copy(this.buffer, 0); },
      //get() { return this._ip_addr || (this._ip_addr = ipaddr.fromByteArray(this.buffer)); },
      //set(value) { this._ip_addr = value; Buffer.from(value.octets).copy(this.buffer, 0); },
      enumerable: true,
      configurable: false,
    });

    //p.set(p.get());

  //} else if (['FT_STRING'].includes(p.type_info.name)) {
  //  p.text = p.buffer.toString('ascii');
  } else if (m = p.type_info.name.match(/^FT_(U)?INT(\d+)$/)) {
    var signed = !m[1];
    var byteLength = parseInt(m[2], 10) / 8;
    // FIXME: hex is sometimes shorter than what we need, so adjust - but why?
    ////byteLength = Math.min(byteLength, p.length);
    byteLength = Math.min(byteLength, p.buffer.length);
    //console.log({p, signed, byteLength});

    // FIXME: why crashing?
    /*
    p.number = signed ? p.buffer.readIntBE(0, byteLength) : p.buffer.readUIntBE(0, byteLength);

    p.get = () => {
      return signed ? p.buffer.readIntBE(0, byteLength) : p.buffer.readUIntBE(0, byteLength)
    };

    p.set = (value) => {
      if (signed)
       p.buffer.writeIntBE(value, 0, byteLength);
     else
       p.buffer.writeUIntBE(value, 0, byteLength);
    }
    */

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
    //console.log(k)
    console.log({k, v: parseField(a[k])})
  }
}

async function convert (capfile) {
  var pcap = fs.readFileSync(`${capfile}.json`, 'utf8');
  pcap = JSON.parse(pcap);
  fs.writeFileSync(`${capfile}-a.json`, JSON.stringify(pcap, null, 2), 'utf8');

  var og_ip = _.memoize(hex => {
    var arr = ipv4base.toByteArray();
    arr[arr.length-1] += ipv4offs++;
    return ipaddr.fromByteArray(arr);
  });

  // FT_IPv4
  var genIP = (hex, field) => {
    var ipa = field.ip_addr;
    if (['private'].includes(ipa.range())) {
      field.ip_addr = og_ip(hex);
    }

    return hex;
  };

  // FT_ETHER
  var genMAC = orig => generateMacAddr().replace(/:/g,'').toLowerCase();

  //var g_ip = _.memoize(genIP);
  var g_ip = genIP;
  var g_mac = _.memoize(genMAC);

  var caches = {
    ip: g_ip.cache,
    mac: g_mac.cache,
  };

var frameData = [];

  const p = _(pcap);
  p.each(frame => {
    const layers = frame._source.layers;

    /*
    //console.log(frame);
    r = _.get(frame, '_source.layers.eth["eth.src_raw"]');
    //console.log(r);
    r = _.get(frame, '_source.layers.eth["eth.dst_raw"]');
    //console.log(r);
*/

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
    frameData.push({layers, data: frameField.buffer});

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
    if (frame._source.layers.tcp) {
      var prt = parseField(frame._source.layers.tcp['tcp.dstport_raw'], frameField);
      prt.prtname = _.find(tables.decodes['tcp.port'], v => v.selector === prt.number);
      console.log(prt.number);
      console.log(prt);
    }

    a = layers.ip;
    b = a;
    //b = frame._source.layers.ip = {};
    remap("ip.{src,dst}", g_ip);

    a = layers.arp;
    //b = a;
    b = layers.arp = {};
    remap("arp.{src,dst}.hw_mac", g_mac);
    remap("arp.{src,dst}.proto_{ipv4,ipv6}", g_ip);


    a = layers.ipv6;
    //b = a;
    b = frame._source.layers.ipv6 = {};
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
    function remapField(fieldName, updater/*, input, output = input*/) {
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

    /*
    for (var k of Object.keys(input)) {
      console.log(k);
    }
    */

/*
    var p = _.zipObject (['hex', 'position', 'length', 'bitmask', 'type'], r);


    //frame._source.layers.eth_raw[0] = mutate(frame._source.layers.eth_raw[0])(p.start, p.end, newaddr);
    var newraw = frame._source.layers.eth_raw[0].splice(p.start, newaddr.length, newaddr);
    frame._source.layers.eth_raw[0] = newraw;
*/

    //delete frame._source.layers.eth;
  });

  write_pcap(frameData, `${capfile}-b.json.pcap`);

  //console.log(caches);

  fs.writeFileSync(`${capfile}-b.json`, JSON.stringify(pcap, null, 2), 'utf8');
}

const NetChecksum = require('netchecksum');

function fixChecksums(layers, frameField) {
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
    //var dns = parseField(layers.dns_raw, frameField);
    //var hdr = parseField(layers.udp_raw, frameField);
    var fld = parseField(layers.udp['udp.checksum_raw'], frameField);
    //var osum = fld.number;

/*
    const pseudo = Buffer.concat([
    srcIp, dstIp, new Buffer([0, 17]), length,
    srcPort, dstPort, length, new Buffer([0, 0]),
    content
    ]);
*/
/*
    const pseudo = Buffer.concat([
      parseField(layers.ip['ip.src_raw'], frameField).buffer,
      parseField(layers.ip['ip.dst_raw'], frameField).buffer,
    */

    fld.number = 0;
    //fld.number = NetChecksum.raw(pseudo);
  }
}

/*
typedef struct pcap_hdr_s {
        guint32 magic_number;   /* magic number
        guint16 version_major;  /* major version number
        guint16 version_minor;  /* minor version number
        gint32  thiszone;       /* GMT to local correction
        guint32 sigfigs;        /* accuracy of timestamps
        guint32 snaplen;        /* max length of captured packets, in octets
        guint32 network;        /* data link type
} pcap_hdr_t;
*/

/*
typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds
        guint32 ts_usec;        /* timestamp microseconds
        guint32 incl_len;       /* number of octets of packet saved in file
        guint32 orig_len;       /* actual length of packet
} pcaprec_hdr_t;
*/

const binstruct = require('binstruct');

const pcap_hdr_t = binstruct
.def({littleEndian:true})
//.def({littleEndian:false})
//.def()
  .uint32('magic_number')
  .uint16('version_major')
  .uint16('version_minor')
  .int32('thiszone')
  .uint32('sigfigs')
  .uint32('snaplen')
  .uint32('network');

const pcaprec_hdr_t = binstruct
  .def({littleEndian:true})
  .uint32('ts_sec')
  .uint32('ts_usec')
  .uint32('incl_len')
  .uint32('orig_len');

async function write_pcap (frames, oname) {

  let writeStream = fs.createWriteStream(oname);

  //var hdr = pcap_hdr_t.wrap(b);
  var hdr = {};
  hdr.magic_number = 0xa1b2c3d4;
  hdr.version_major = 2;
  hdr.version_minor = 4;
  hdr.network = 1; // ethernet
  hdr.snaplen = 65535; // ?
  writeStream.write(pcap_hdr_t.write(hdr));

  frames.forEach(frame => {

    var ts = [];
    if (frame.layers.frame)
      ts = frame.layers.frame['frame.time_epoch'].split('.').map(v => parseInt(v, 10));

    console.log(ts);

    var rec_hdr = {
      ts_sec: ts[0],
      ts_usec: ts[1]/1000,
      incl_len: frame.data.length,
      orig_len: frame.data.length,
    };
    writeStream.write(pcaprec_hdr_t.write(rec_hdr));
    writeStream.write(frame.data);

  });

  writeStream.end();
}

/*
String.prototype.splice = function(startIndex,length,insertString){
    return this.substring(0,startIndex) + insertString + this.substring(startIndex + length);
};
*/

async function run (capfile) {
  await execa.shell(`tshark -r ${capfile} -T json -x > ${capfile}.json`);
  //await execa.shell(`tshark -r ${capfile} -T jsonraw > ${capfile}.json`);
  convert(capfile);
  //await execa.shell(`python json2pcap.py ${capfile}-b.json`);

  //diff -u data/cloudflare.pcap-a.json data/cloudflare.pcap-b.json
  //old: diff -u data/cloudflare-a.json data/cloudflare-b.json
}

//run('data/nb6-http.pcap');

module.exports = run;
