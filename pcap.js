const binstruct = require('binstruct');
const pcap_tables = require('./tables.json');

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

  /*
  typedef struct pcaprec_hdr_s {
          guint32 ts_sec;         /* timestamp seconds
          guint32 ts_usec;        /* timestamp microseconds
          guint32 incl_len;       /* number of octets of packet saved in file
          guint32 orig_len;       /* actual length of packet
  } pcaprec_hdr_t;
  */
const pcaprec_hdr_t = binstruct
  .def({littleEndian:true})
  .uint32('ts_sec')
  .uint32('ts_usec')
  .uint32('incl_len')
  .uint32('orig_len');

module.exports = {pcap_tables, pcap_hdr_t, pcaprec_hdr_t};
