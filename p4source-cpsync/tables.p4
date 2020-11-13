table l3_forward {
	reads { 
        ipv4.srcAddr: exact;
		ipv4.dstAddr : exact;
	}
	actions {
		_nop; 
        forward;
        send_to_cpu;
	}
}
table l3_forward_udp {
	reads { 
        ipv4.srcAddr: exact;
		ipv4.dstAddr : exact;
        udp.dstPort : exact;
        udp.srcPort : exact;
	}
	actions {
		_nop; 
        forward;
        send_to_cpu;
	}	
}
table l3_forward_icmp {
	reads { 
        ipv4.srcAddr: exact;
		ipv4.dstAddr : exact;
	}
	actions {
        forward;
        send_to_cpu;
	}	
}

table send_to_cpu_tbl {
    reads {
    }
    actions {
        send_to_cpu;
    }
}
table copy_to_cpu_table {
    reads {
    }
    actions {
        copy_to_cpu;
    }
}
table disc_pkt_to_cpu_tbl {
    reads {

    }
    actions {
        disc_pkt_to_cpu;
    }
}
table disc_pkt_to_cpu_no_timing_tbl {
    reads {

    }
    actions {
        disc_pkt_to_cpu_no_timing;
    }
}

table drop_tbl {
    reads {

    }
    actions {
        _drop;
    }
}
table l3_forward_tcp {
	reads { 
        ipv4.srcAddr: exact;
		ipv4.dstAddr : exact;
        tcp.dstPort : exact;
        tcp.srcPort : exact;
	}
	actions {
		_nop; 
        forward;
        send_to_cpu;
	}	
}

table send_digest_tbl {
    reads {
    }
    actions {
        send_digest;
    }
}
table store_digest_tbl {
    reads {
    }
    actions {
        store_digest;
    }
}
table read_digest_send_tbl {
    reads {
    }
    actions {
        read_digest_send;
    }
}
table monitor_read_data_tbl {
    reads {
    }
    actions {
        monitor_read_data;
    }
}


table handle_discovery_packet_table {
    reads {

    }
    actions {
        handle_discovery_packet;
    }
    size: 0;
}
table plus_total_table {
    reads {

    }
    actions {
        plus_total;
    }
}

table plus_total_table_proxyStateless {
    reads {
    }
    actions {
        plus_total_proxyStateless;
    }
}
table plus_total_table_packetCounter {
    reads {
    }
    actions {
        plus_total_packetCounter;
    }
}table plus_total_table_fwStateless {
    reads {
    }
    actions {
        plus_total_fwStateless;
    }
}
table plus_total_table_fwStateful {
    reads {
    }
    actions {
        plus_total_fwStateful;
    }
}
table set_flowID_tbl {
    reads {
        ipv4.srcAddr: exact;
        ipv4.dstAddr: exact;
        ipv4.protocol: exact;
        port_metadata.srcPort: exact;
        port_metadata.dstPort: exact;
    }
    actions {
        _nop;
        set_flowID;
    }
}

table remove_flowID_tbl {
    reads {
        flowID.flowID: exact;
    }
    actions {
        _nop;
        remove_flowID;
    }
}
table route_flowID_tbl {
    reads {
        flowID.flowID: exact;
    }
    actions {
        send_to_cpu;
        route_flowID;
    }
}

table set_port_metadata_tcp_tbl {
    reads {
    }
    actions {
        set_port_metadata_tcp;
    }
}
table set_port_metadata_udp_tbl {
    reads {
    }
    actions {
        set_port_metadata_udp;
    }
}

table set_port_metadata_rest_tbl {
    reads {
    }
    actions {
        set_port_metadata_rest;
    }
}
table egress_set_port_metadata_tcp_tbl {
    reads {
    }
    actions {
        set_port_metadata_tcp;
    }
}
table egress_set_port_metadata_udp_tbl {
    reads {
    }
    actions {
        set_port_metadata_udp;
    }
}

table egress_set_port_metadata_rest_tbl {
    reads {
    }
    actions {
        set_port_metadata_rest;
    }
}

table write_flowID_to_regs_table {
    reads {

    }
    actions {
        write_flowID_to_regs;
    }
}


table calc_net_hash_normal_table {
    reads {

    }
    actions {
        calc_net_hash_normal;
    }
}
table calc_net_hash_mig_table {
    reads {

    }
    actions {
        calc_net_hash_mig;
    }
}
table set_mig_seq_table {
    reads {

    }
    size: 0;
    actions {
        set_mig_seq;
    }
}

table sendPacketUpdate_table {
    reads {

    }
    size: 0;
    actions {
        sendPacketUpdate;
    }
}

table readPacketStats_table {
    reads {
        flowID.flowID: exact;
    }
    actions {
        readPacketStats;
    }
}


//////////////////////////PROXY SPECIFIC THINGS
table apply_proxy_stateless_tbl {
    reads {
        flowID.flowID:exact;
        ipv4.dstAddr:exact;
        ipv4.srcAddr: exact;
    }
    actions {
        apply_proxy_stateless;
        _nop;
    }
}
table apply_packetCounter_stateful_flowID_tbl {
    reads {
        flowID.flowID: exact;
    }
    actions {
        apply_packetCounter_stateful_flowID;
        _nop;
    }
}
table apply_packetCounter_stateful_tbl {
    reads {
        flowID.flowID: exact;
    }
    actions {
        apply_packetCounter_stateful;
        _nop;
    }
}


table read_sid_table {
    reads {

    }
    actions {
        _nop;
        read_sid;
    }
}



///// migration tables
table add_proxyStateless_header_table {
    reads {

    }
    actions {
        add_proxyStateless_header;
    }
    size: 0;
}

table add_packetCounter_header_table {
    reads {

    }
    actions {
        add_packetCounter_header;
    }
    size: 0;
}

table update_packetCounter_header_table {
    reads {

    }
    actions {
        add_packetCounter_header;
    }
    size: 0;
}

table read_seqID_from_reg_table {
    reads {

    }
    actions {
        read_seqID_from_reg;
    }
}
table store_seqID_to_reg_table {
    reads {

    }
    actions {
        store_seqID_to_reg;
    }
}

table send_mig_ack_table {
    reads {
    }
    size: 0;
    actions {
        send_mig_ack;
    }
}

table send_pkt_to_sw_table {
    reads {
        _mig_metadata.migdstsw: exact;
    }
    actions {
        send_pkt_to_sw;
        _nop;
    }
}

table route_mig_flowID {
    reads{
        _mig_flow_recv.flowID: exact;
    }
    actions {
        route_flowID;
    }
}

table route_mig_forward_flowID {
    reads{
        _mig_flow_recv.flowID: exact;
    }
    actions {
        route_flowID;
    }
}

table test_mirror {
    reads {

    }
    actions {
        add_sessID;
    }
}

table test_clone {
    reads {

    }
    size: 0;
    actions {
        clone_ing_2_eg;
    }
}

table rem_ipv4_test {
    reads {

    }
    size: 0;
    actions {
        remove_ipv4_test;
    }
}

table set_mig_protoc_zero_f_table {
    reads {

    }
    size: 0;
    actions {
        set_mig_protoc_zero_f;
    }
}
table plus_seqID_table {
    reads {

    }
    size: 0;
    actions {
        plus_seqID;
    }
}

table mig_packetful_flowID_write_tbl {
    reads {
    }
    size: 0;
    actions {
        mig_packetful_flowID_write;
    }
}

table clone_pass_update_table {
    reads {
    }
    size: 0;
    actions {
        clone_pass_update;
    }
}
table mig_upd_pkt_egress_table {
    reads {
        _mig_flow_recv.migSessionID: exact;
    }
    actions {
        mig_upd_pkt_egress;
        _nop;
    }
}

table clone_pkt_set_hash_table {
    reads {
    }
    actions {
        clone_pkt_set_hash;
    }
}
table flow_migrate_timing_process_table {
    reads {
    }
    actions {
        flow_migrate_timing_process;
    }
}
table clone_switch_time_table {
    reads {
    }
    actions {
        clone_switch_time;
    }
}
table forward_time_info_to_cpu_table {
    reads {
    }
    actions {
        ingress_flow_migrate_timing_process;
    }
}
table plus_migration_table {
    reads {
    }
    actions {
        plus_migration;
    }
}


table send_mig_ack_forward_state_tbl {
    reads {
    }
    actions {
        send_forward_ack;
    }
}

table migrate_forward_resubmit_table {
    reads {
    }
    actions {
        migrate_forward_resubmit;
    }
}
table strip_mig_headers_table {
    reads {
    }
    actions {
        strip_mig_headers;
    }
}
table forward_mig_pkt_tbl {
    reads {
        _mig_flow_recv.migSessionID: exact;
    }
    actions {
        forward_mig_pkt;
        _nop;
    }
}
table forward_mig_pkt_set_sessid_tbl {
    reads {
    }
    actions {
        forward_mig_pkt_set_sessid;
        _nop;
    }
}
table recalculate_flowID_hash_after_set_flowID_tbl {
    reads {
    }
    actions {
        recalculate_flowID_hash_after_set_flowID;
    }
}

table read_mig_sid_table {
    reads {

    }
    actions {
        read_mig_sid;
    }
}






