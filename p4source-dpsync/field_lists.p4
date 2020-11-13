field_list digest_field_list {
    //standard_metadata;
    digest_pkt.enq_timestamp;
    digest_pkt.enq_qdepth;
    digest_pkt.deq_qdepth;
    digest_pkt.deq_timedelta;
    digest_pkt.monitorts;
}

field_list pkt_update_digest {
    int_pktstats.threshold;
    int_pktstats.numPackets;
    int_pktstats.timestamp;
    int_pktstats.flowID;
}

field_list flow_hash_list_tcp {
    ipv4.srcAddr;
    ipv4.dstAddr;
    tcp.srcPort;
    tcp.dstPort;
}

field_list mig_packetCounter_field_list {
    networkinfo.migSrcPort;
    networkinfo.migDstPort;
    networkinfo.migSrcIP;
    networkinfo.migDstIP;
    networkinfo.migipProtocol;
}
field_list mig_packetCounter_flowID_field_list {
    networkinfo.flowID;
}

field_list packetCounter_flowID_field_list {
    flowID.flowID;
}
field_list packetCounter_field_list {
    port_metadata.srcPort;
    port_metadata.dstPort;
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
}
field_list_calculation packetCounter_calculation {
    input {
        packetCounter_field_list;
    }
    algorithm: crc32;
    output_width: 32;
}
field_list_calculation packetCounter_flowID_calculation {
    input {
        packetCounter_flowID_field_list;
    }
    algorithm: crc32;
    output_width: 32;
}

field_list_calculation mig_packetCounter_flowID_calculation {
    input {
        mig_packetCounter_flowID_field_list;
    }
    algorithm: crc32;
    output_width: 32;
}


field_list clone_test_list {
}

field_list flow_hash_list_udp {
    ipv4.srcAddr;
    ipv4.dstAddr;
    udp.srcPort;
    udp.dstPort;
}

field_list ipv4_hash_fields {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list flowid_hash_routing_metadata_field_list {
    networkinfo.flowID;
}

field_list_calculation flowid_hash_routing_metadata_hash {
    input {
        flowid_hash_routing_metadata_field_list;
    }
    algorithm: crc32;
    output_width: 32;
}

field_list migration_tbl_flowID {
    flowID.flowID;
}
field_list migration_tbl_flowID_set_flowID {
    flowID.flowID;
}

field_list_calculation migration_tbl_flowID_calculation {
    input {
        migration_tbl_flowID;
    }
    algorithm: crc32;
    output_width: 32;
}
field_list_calculation migration_tbl_flowID_calculation_set_flowID {
    input {
        migration_tbl_flowID_set_flowID;
    }
    algorithm: crc32;
    output_width: 32;
}



field_list_calculation ipv4_checksum {
	input {
		ipv4_hash_fields;
	}
	algorithm: csum16;
	output_width: 16;
}

field_list tcp_checksum_list {
        ipv4.srcAddr;
        ipv4.dstAddr;
        8'0;
        ipv4.protocol;
        routing_metadata.tcpLength;
        tcp.srcPort;
        tcp.dstPort;
        tcp.seqNo;
        tcp.ackNo;
        tcp.dataOffset;
        tcp.res;
        tcp.flags;
        tcp.window;
        tcp.urgentPtr;
        payload;
}

field_list_calculation tcp_checksum {
    input {
        tcp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}


field_list mirror_fld_list {
    //local_metadata.mirror_session;
    //intrinsic_metadata;
    //intrinsic_metadata.ingress_global_timestamp;
}

field_list mig_forward_field_list{
    //_mig_metadata.stripMigHeaders;
    //_mig_metadata;
}