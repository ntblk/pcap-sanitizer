const binstruct = require('binstruct');

const pcap_tables = require('./tables.json');

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

module.exports = {pcap_tables, pcap_hdr_t, pcaprec_hdr_t};
