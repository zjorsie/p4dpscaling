header_type queueing_metadata_t {
    fields {
        enq_timestamp : 48;
        enq_qdepth : 19;
        deq_timedelta : 32;
        deq_qdepth : 19;
        //padding: 6;
        //qid : 6;
    }
}

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}
header_type _ss_m_t {
    fields {
        state: 8;
        pktnum: 32;
    }
    
}

header_type _ss_id_t {
    fields {
        hdr: 16;
        data: 32;
    }
    
}

header_type digest_pkt_t {
    fields {
        enq_timestamp: 48;
        enq_qdepth: 48;
        deq_qdepth: 48;
        deq_timedelta: 48;
        prev_deq_timedelta: 48;
        send_digest: 48;
        monitorts: 48;
    }
}

header_type icmp_t {
    fields {
        typeCode : 16;
        hdrChecksum : 16;
    }
}

header_type packetCounter_metadata_t {
    fields {
        flowHash: 16;
        packetNum: 32;
    }
}

header_type new_metadata_t {
    fields {
        sid:8;
        flowHash:16;
        init_without_flowID:8;
    }
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header_type pkt_in_t {
    fields {
        ingress_port: 16;
    }
}
header_type pktStats_t {
    fields {
        pktstats: 32;
        packetCounter: 32;
        ProxyStateless: 32;
        FwStateless:32;
        FwStateful:32;
        FwMigration:32;
    }
}
header_type int_pktstats_t{
    fields {
        numPackets: 32;
        threshold: 32;
        flowID: 32;
        timestamp: 48;
    }
}
header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16;
        checksum : 16;
    }
}
header_type routing_metadata_t {
    fields {
        flowID_hash: 32;
        tcpLength : 16;
    }
}

header_type flowID_t {
    fields {
        flowhdr: 16;
        flowID: 32;
    }
}
header_type port_metadata_t {
    fields {
        srcPort: 16;
        dstPort: 16;
        flowID: 32;
        set: 8;
    }
}

header_type _mig_flow_recv_t {
    fields {
        flowhdr: 16;
        flowID: 32;
        subProtocol: 8;
        sequenceID: 16;
        VNFID: 8;
        migSessionID: 8;
    }
}

header_type _mig_metadata_t {
    fields {
        migStatus: 8;
        migSessionID: 8;
        regSeqID: 16;
        migFlowIDBack: 32;
        migTableHash: 32;
        stripMigHeaders: 8;
        migsrcsw: 8;
        migdstsw: 8;
        cpuUpdate: 8;
    }
}

header_type _mig_packetCounter_metadata_t {
    fields {
        hash: 32;
    }
}

header_type networkinfo_t {
    fields {
        flowID: 32;
        migSrcIP: 32;
        migDstIP: 32;
        migSrcPort: 16;
        migDstPort: 16;
        migipProtocol: 8; // 17byte
    }
}

header_type migrate_packetCounter_values_t {
    fields {
        nrPackets: 32;
    }
}

header_type migrate_fwStateless_t {
    fields {
        test1:8;
    }
}

header_type migrate_fwStateful_t {
    fields {
        test1:8;
    }
}

header_type migrate_timing_t {
    fields {
        ts:48;
    }
}

header_type local_metadata_t {
    fields {
        cpu_code : 16; // Code for packet going to CPU
        port_type : 4; // Type of port: up, down, local...
        ingress_error : 1; // An error in ingress port check
        was_mtagged : 1; // Track if pkt was mtagged on ingr
        copy_to_cpu : 1; // Special code resulting in copy to CPU
        bad_packet : 1; // Other error indication
        color : 8; // For metering
        mirror_session: 8; // for mirroring
    }
}


header_type intrinsic_metadata_t {
    fields {
        ingress_global_timestamp : 48;
        egress_global_timestamp : 48;
        mcast_grp : 16;
        egress_rid : 16;
    }
}
header ethernet_t ethernet;
header ipv4_t ipv4;
header icmp_t icmp;
header tcp_t tcp;
header udp_t udp;
header pkt_in_t pkt_in;
header pktStats_t pktStats;
header flowID_t flowID;
header _mig_flow_recv_t _mig_flow_recv;
header migrate_timing_t migrate_timing;
header migrate_packetCounter_values_t migrate_packetCounter_values;
header networkinfo_t networkinfo;
header migrate_fwStateless_t migrate_fwStateless;
header migrate_fwStateful_t migrate_fwStateful;
header _ss_id_t _ss_id;
metadata packetCounter_metadata_t packetCounter_metadata;
metadata new_metadata_t new_metadata;
metadata _mig_metadata_t _mig_metadata;
metadata _mig_packetCounter_metadata_t _mig_packetCounter_metadata;
metadata local_metadata_t local_metadata;
metadata routing_metadata_t routing_metadata;
metadata port_metadata_t port_metadata;
metadata queueing_metadata_t queueing_metadata;
metadata digest_pkt_t digest_pkt;
metadata pktStats_t pktStats_metadata;
metadata intrinsic_metadata_t intrinsic_metadata;
metadata int_pktstats_t int_pktstats;
metadata _ss_m_t _ss_m;
