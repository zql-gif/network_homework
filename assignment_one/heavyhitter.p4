/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;

#define CM_SKETCH_ENTRIES 256
#define CM_SKETCH_BIT_WIDTH 32
#define HEAVY_HITTER_THRESHOLD 100
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    //TODO : Define the metadata we need to use
    bit<32> reg_pos_1;
    bit<32> reg_pos_2;
    bit<32> reg_val_1;
    bit<32> reg_val_2;
    bit<32> mini;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                  out headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

      state start {
          transition parse_ethernet;
      }

      state parse_ethernet {
          packet.extract(hdr.ethernet);
          transition select(hdr.ethernet.etherType) {
              TYPE_IPV4: parse_ipv4;
              default: accept;
          }
      }

      state parse_ipv4 {
          packet.extract(hdr.ipv4);
          transition select(hdr.ipv4.protocol){
              TYPE_TCP: tcp;
              default: accept;
          }
      }

      state tcp {
         packet.extract(hdr.tcp);
         transition accept;
      }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    register<bit<CM_SKETCH_BIT_WIDTH>>(CM_SKETCH_ENTRIES) sketch_array_1;
    register<bit<CM_SKETCH_BIT_WIDTH>>(CM_SKETCH_ENTRIES) sketch_array_2;



    action update_sketch(){
        //TODO: Hash the 5-tuple(srcIP, dstIP, protocol, srcPort, dstPort) of the packet
        hash(meta.reg_pos_1, HashAlgorithm.crc16, (bit<32>)0, {hdr.ipv4.srcAddr,
                                                           hdr.ipv4.dstAddr,
                                                           hdr.tcp.srcPort,
                                                           hdr.tcp.dstPort,
                                                           hdr.ipv4.protocol},
                                                           (bit<32>)CM_SKETCH_ENTRIES);


        hash(meta.reg_pos_2, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr,
                                                           hdr.ipv4.dstAddr,
                                                           hdr.tcp.srcPort,
                                                           hdr.tcp.dstPort,
                                                           hdr.ipv4.protocol},
                                                           (bit<32>)CM_SKETCH_ENTRIES);
        //TODO: Read from sketch's counter array and update the value.
        sketch_array_1.read(meta.reg_val_1,meta.reg_pos_1);
        sketch_array_2.read(meta.reg_val_2,meta.reg_pos_2);
        sketch_array_1.write(meta.reg_pos_1,meta.reg_val_1 + 1);
        sketch_array_2.write(meta.reg_pos_2,meta.reg_val_2 + 1);
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        // TODO: Define the logic of L3 forwarding: update the outgoing port, mac address and TTL of the packet.
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
      if (hdr.ipv4.isValid()){
          if (hdr.tcp.isValid()){
            //TODO: Read from sketch's counter array and update the value.
            update_sketch();


            //TODO: Select the minimum value among the counters as the estimated value of the flow.
            if(meta.reg_val_2 < meta.reg_val_1){
                meta.mini = meta.reg_val_2;
            }else{
                meta.mini = meta.reg_val_1;
            }


            //TODO: Assuming that the estimated value of the flow is greater than the threshold, the packet is discarded. Otherwise, L3 forwarding is performed.
            if(meta.mini < HEAVY_HITTER_THRESHOLD)
              ipv4_lpm.apply();
            else
              drop();
          }
      }






    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {

        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.tos,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
