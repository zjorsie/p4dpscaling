parser start {
    return select(current(0,16)) {
        FLOWID_HDR: parse_flowID;
        MIG_HDR: parse_mig_flow_recv;
        default: parse_ethernet;
    }  
}

parser parse_mig_flow_recv {
    extract(_mig_flow_recv);
    return select(latest.subProtocol) {
        MIGST_FORWARD: parse_flowID;
        default: parse_netinfo;

    }
}

parser parse_netinfo {
    extract(networkinfo);
    return select(_mig_flow_recv.VNFID) {
        VNF_PROXYLESS: parse_mig_proxyStateless_value;
        VNF_PACKETFUL: parse_mig_packetCounter_value;
        VNF_FWLESS: parse_mig_fwStateless_value;
        VNF_FWFUL: parse_mig_fwStateful_value;
        default: parse_timestamp;
    }
}
parser parse_timestamp {
    extract(migrate_timing);
    return ingress;
}
parser parse_mig_proxyStateless_value {
    // stateless. Just return to parse_flowID:
    return ingress;
}
parser parse_mig_packetCounter_value {
    // statefull. parse values:
    extract(migrate_packetCounter_values);
    return ingress;
}
parser parse_mig_fwStateless_value {
    // stateless. Just return to parse_flowID:
    return ingress;
}
parser parse_mig_fwStateful_value {
    // stateless. Just return to parse_flowID:
    return ingress;
}

parser parse_flowID {
    extract(flowID);
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_SEND_CPU: parse_pktin;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    set_metadata(routing_metadata.tcpLength, latest.totalLen);
    return select(latest.fragOffset, latest.ihl, latest.protocol) {
        IP_PROTOCOLS_IPHL_ICMP : parse_icmp;
        IP_PROTOCOLS_IPHL_TCP : parse_tcp;
        IP_PROTOCOLS_IPHL_UDP : parse_udp;
        default: ingress;
    }
}

parser parse_pktin {
    extract(pkt_in);
    
    return select (ethernet.etherType) {
         ETHERTYPE_SEND_CPU : ingress;
         0xfffe : parse_pktStats;
         default: ingress;
    }
}

parser parse_pktStats {
    extract(pktStats);
    return ingress;
}

parser parse_icmp {
    extract(icmp);
    return select(latest.typeCode) { 
        default: ingress;
    }
} 

parser parse_tcp {
    extract(tcp);
    return select(latest.dstPort) { 
        default: ingress;
    }
}

parser parse_udp {
    extract(udp);
    return select(latest.dstPort) { 
        default: ingress;
    }
}