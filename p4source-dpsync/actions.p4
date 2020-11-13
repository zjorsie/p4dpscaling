action _drop() {
	drop();
}

action _nop() {
}

action forward(port) {
	modify_field(standard_metadata.egress_spec, port);
}

action send_to_cpu() {
    modify_field(standard_metadata.egress_spec, CPU_PORT);
    add_header(pkt_in);
    modify_field(pkt_in.ingress_port,standard_metadata.ingress_port);
}

action copy_to_cpu() {
    modify_field(standard_metadata.egress_spec, CPU_PORT);
}

action store_digest() {
    register_write(usage_info, 1, queueing_metadata.enq_qdepth);
    register_write(usage_info, 2, queueing_metadata.deq_qdepth);
    register_write(usage_info, 3, queueing_metadata.deq_timedelta);
    register_write(usage_info, 4, queueing_metadata.enq_timestamp);
    register_write(usage_info, 0, 0xffff);
}

action read_digest_send() {
    register_read(digest_pkt.send_digest,usage_info,0);
    register_read(digest_pkt.prev_deq_timedelta ,usage_info, 5);
    register_read(digest_pkt.deq_timedelta ,usage_info, 4);
    register_read(digest_pkt.enq_qdepth, usage_info, 1);
    register_read(digest_pkt.deq_qdepth, usage_info, 2);
    modify_field(digest_pkt.enq_timestamp, intrinsic_metadata.ingress_global_timestamp);
}
action monitor_read_data(dequeuedepthlimit, timedelta_max) {
    // this action reads
    // - time spent in queue threshold
    // - queue length threshold
    modify_field(digest_pkt.deq_qdepth, dequeuedepthlimit);
    modify_field(digest_pkt.deq_timedelta, timedelta_max);
}
action send_digest() {
    register_read(digest_pkt.enq_qdepth, usage_info, 1);
    register_read(digest_pkt.deq_qdepth, usage_info, 2);
    register_read(digest_pkt.deq_timedelta, usage_info, 3);
    register_read(digest_pkt.enq_timestamp, usage_info, 4);
    register_read(pktStats.pktstats, packet_stats, 0);
    modify_field(digest_pkt.enq_timestamp, intrinsic_metadata.ingress_global_timestamp);
    // clone packet to ingress and send to CPU
    generate_digest(1024,digest_field_list);
    register_write(usage_info, 0, 0x0000);

    //register_write(usage_info, 5, digest_pkt.enq_timestamp);
}

action disc_pkt_to_cpu_no_timing() {
    modify_field(ethernet.etherType, 0xeffe);
    modify_field(standard_metadata.egress_spec, CPU_PORT);
    add_header(pkt_in);
    modify_field(pkt_in.ingress_port,standard_metadata.ingress_port);
}
action disc_pkt_to_cpu() {
    modify_field(ethernet.etherType, 0xffee);
    modify_field(standard_metadata.egress_spec, CPU_PORT);
    add_header(pkt_in);
    modify_field(pkt_in.ingress_port,standard_metadata.ingress_port);
    add_header(pktStats);
    register_read(pktStats.pktstats, packet_stats, 0);
    add_to_field(pktStats.pktstats, 1); //Include current packet in statistics
    register_write(packet_stats, 0, 0);
    
    register_read(pktStats.packetCounter, packet_stats, PACKETCOUNTAPPSTATEFUL);
    register_write(packet_stats, PACKETCOUNTAPPSTATEFUL, 0);
    register_read(pktStats.ProxyStateless, packet_stats, PROXYAPPSTATELESS);
    register_write(packet_stats, PROXYAPPSTATELESS, 0);
    register_read(pktStats.FwStateless, packet_stats, FWAPPSTATELESS);
    register_write(packet_stats, FWAPPSTATELESS, 0);
    register_read(pktStats.FwStateful, packet_stats, FWAPPSTATEFUL);
    register_write(packet_stats, FWAPPSTATEFUL, 0);
    register_read(pktStats.FwMigration, packet_stats, FWMIGRATION);
    register_write(packet_stats, FWMIGRATION, 0);
    

}
action plus_migration() {
    register_read(pktStats_metadata.FwMigration, packet_stats, FWMIGRATION);
    add_to_field(pktStats_metadata.FwMigration, 1);
    register_write(packet_stats, FWMIGRATION, pktStats_metadata.FwMigration);
}

action plus_total() {
    register_read(pktStats_metadata.pktstats,packet_stats, 0);
    add_to_field(pktStats_metadata.pktstats, 1);
    register_write(packet_stats, 0, pktStats_metadata.pktstats);
}
action handle_discovery_packet() {
    modify_field(standard_metadata.egress_spec, pkt_in.ingress_port);
}
action set_flowID(flowid) {
    add_header(flowID);
    modify_field(flowID.flowID, flowid);
    //modify_field(flowID.flowID, 0x00);
    modify_field(flowID.flowhdr, FLOWID_HDR);
}

action recalculate_flowID_hash_after_set_flowID() {
    modify_field_with_hash_based_offset(routing_metadata.flowID_hash, 0, migration_tbl_flowID_calculation, HASH_SIZE);
}
action set_port_metadata_tcp() {
    modify_field(port_metadata.srcPort,tcp.srcPort);
    modify_field(port_metadata.dstPort,tcp.dstPort);
    modify_field(port_metadata.set,0xff);
}
action set_port_metadata_udp() {
    modify_field(port_metadata.srcPort,udp.srcPort);
    modify_field(port_metadata.dstPort,udp.dstPort);
    modify_field(port_metadata.set,0xff);
}
action set_port_metadata_rest() {
    modify_field(port_metadata.srcPort,143);
    modify_field(port_metadata.dstPort,143);
    modify_field(port_metadata.set,0xff);
}

action remove_flowID() {
    remove_header(flowID);
}

action route_flowID(outPort) {
    modify_field(standard_metadata.egress_spec,outPort);
}


//////////// CODE FOR DETECTION OF SERVICE STATUS //////////////////////
action plus_total_packetCounter() {
    register_read(pktStats_metadata.pktstats,packet_stats, PACKETCOUNTAPPSTATEFUL);
    add_to_field(pktStats_metadata.pktstats, 1);
    // turn off for debug purposes
    register_write(packet_stats, PACKETCOUNTAPPSTATEFUL, pktStats_metadata.pktstats);
}
action plus_total_proxyStateless() {
    register_read(pktStats_metadata.pktstats,packet_stats, PROXYAPPSTATELESS);
    add_to_field(pktStats_metadata.pktstats, 1);
    // turn off for debug purposes
    register_write(packet_stats, PROXYAPPSTATELESS, pktStats_metadata.pktstats);
}
action plus_total_fwStateful() {
    register_read(pktStats_metadata.pktstats,packet_stats, FWAPPSTATEFUL);
    add_to_field(pktStats_metadata.pktstats, 1);
    // turn off for debug purposes
    register_write(packet_stats, FWAPPSTATEFUL,pktStats_metadata.pktstats);
}
action plus_total_fwStateless() {
    register_read(pktStats_metadata.pktstats,packet_stats, FWAPPSTATELESS);
    add_to_field(pktStats_metadata.pktstats, 1);
    // turn off for debug purposes
    register_write(packet_stats, FWAPPSTATELESS,pktStats_metadata.pktstats);
}


///////// CODE FOR APP modify THINGS ///////////////

///////// CODE FOR APP SPECIFIC THINGS ///////////////

action apply_proxy_stateless(mac_Addr, new_dst) {
    // proxy dst is new src address
    modify_field(ipv4.srcAddr, ipv4.dstAddr);
    modify_field(ipv4.dstAddr, new_dst);
    // change the mac dst to src addr:
    modify_field(ethernet.srcAddr, ethernet.dstAddr);
    // rewrite destination mac addr
    modify_field(ethernet.dstAddr,mac_Addr);
    register_read(pktStats_metadata.pktstats,packet_stats, PROXYAPPSTATELESS);
    add_to_field(pktStats_metadata.pktstats, 1);
    // turn off for debug purposes
    register_write(packet_stats, PROXYAPPSTATELESS, pktStats_metadata.pktstats);
}

action apply_packetCounter_stateful() {
    // calculate hash
    modify_field_with_hash_based_offset(packetCounter_metadata.flowHash, 0, packetCounter_calculation, HASH_SIZE);
    // read counter
    register_read(packetCounter_metadata.packetNum, reg_packetCounter, packetCounter_metadata.flowHash);
    // add one to counter
    add_to_field(packetCounter_metadata.packetNum, 1);
    // write back to memory
    register_write(reg_packetCounter, packetCounter_metadata.flowHash, packetCounter_metadata.packetNum);
    // update internal counters...
    register_read(pktStats_metadata.pktstats,packet_stats, PACKETCOUNTAPPSTATEFUL);
    add_to_field(pktStats_metadata.pktstats, 1);
    // turn off for debug purposes
    register_write(packet_stats, PACKETCOUNTAPPSTATEFUL, pktStats_metadata.pktstats);
}

action apply_packetCounter_stateful_flowID() {
    modify_field_with_hash_based_offset(packetCounter_metadata.flowHash, 0, packetCounter_flowID_calculation, HASH_SIZE);
    // read counter
    register_read(packetCounter_metadata.packetNum, reg_packetCounter, packetCounter_metadata.flowHash);
    // add one to counter
    add_to_field(packetCounter_metadata.packetNum, 1);
    // write back to memory
    register_write(reg_packetCounter, routing_metadata.flowID_hash, packetCounter_metadata.packetNum);

    // update internal counters...
    register_read(pktStats_metadata.pktstats,packet_stats, PACKETCOUNTAPPSTATEFUL);
    add_to_field(pktStats_metadata.pktstats, 1);
    // turn off for debug purposes
    register_write(packet_stats, PACKETCOUNTAPPSTATEFUL, pktStats_metadata.pktstats);
}

///////// code for migration ///////////////////
action calc_net_hash_normal() {
    // this function only fills the routing_metadata.flowID_hash variable 
    // and reads the migration state and session from the table
    modify_field_with_hash_based_offset(routing_metadata.flowID_hash, 0, migration_tbl_flowID_calculation, HASH_SIZE);
    register_read(_mig_metadata.migStatus, flowTable, routing_metadata.flowID_hash);
    register_read(_mig_metadata.migSessionID, flowSession, routing_metadata.flowID_hash);
    modify_field(new_metadata.init_without_flowID, 0x00);
}

action readPacketStats(THRESHOLD) {
    register_read(int_pktstats.numPackets, flowNums, routing_metadata.flowID_hash);
    add_to_field(int_pktstats.numPackets, 1);
    register_write(flowNums,routing_metadata.flowID_hash,int_pktstats.numPackets);
    //add_to_field(int_pktstats.numPackets, -1);
    modify_field(int_pktstats.threshold, THRESHOLD);
    modify_field(int_pktstats.flowID, flowID.flowID);
    modify_field(int_pktstats.timestamp, intrinsic_metadata.ingress_global_timestamp);
}

action sendPacketUpdate() {
    // reset counter and send digest.
    generate_digest(1024, pkt_update_digest);
    register_write(flowNums,routing_metadata.flowID_hash,0);
}
action calc_net_hash_mig() {
    modify_field_with_hash_based_offset(routing_metadata.flowID_hash, 0, flowid_hash_routing_metadata_hash, HASH_SIZE);
    register_read(_mig_metadata.migStatus, flowTable, routing_metadata.flowID_hash);
    register_read(_mig_metadata.migSessionID, flowSession, routing_metadata.flowID_hash);
    register_read(_mig_metadata.cpuUpdate, flowUpdateCounter, routing_metadata.flowID_hash);
    modify_field(new_metadata.init_without_flowID, 0xff);
}
action write_flowID_to_regs() {
    // writes info to registers
    // writes info to metadata
    
    modify_field(_mig_metadata.migStatus, _mig_flow_recv.subProtocol);
    modify_field(_mig_metadata.migSessionID, _mig_flow_recv.migSessionID);
    register_write(flowTable, routing_metadata.flowID_hash, _mig_metadata.migStatus);
    register_write(flowSession, routing_metadata.flowID_hash, _mig_flow_recv.migSessionID);
    register_write(flowVNFID, routing_metadata.flowID_hash, _mig_flow_recv.VNFID);
}

// VNF specific migration header
action add_proxyStateless_header() {
    // don't do anything. proxystateless is not stateful.
}

action add_packetCounter_header() {
    // calculate relevant information:

    // add relevant data for packetCounter
    add_header(migrate_packetCounter_values);

    // calculate_hash and fill value fields
    modify_field_with_hash_based_offset(packetCounter_metadata.flowHash, 0, mig_packetCounter_flowID_calculation, HASH_SIZE);
    register_read(migrate_packetCounter_values.nrPackets, reg_packetCounter, packetCounter_metadata.flowHash);
}

action read_seqID_from_reg() {
    register_read(_mig_metadata.regSeqID, flowReceiveID, routing_metadata.flowID_hash);
}

action store_seqID_to_reg() {
    modify_field_with_hash_based_offset(routing_metadata.flowID_hash, 0, flowid_hash_routing_metadata_hash, HASH_SIZE);
    register_write(flowReceiveID, routing_metadata.flowID_hash, _mig_flow_recv.sequenceID);
}

action resend_mig_ack_pkt () {
    modify_field_with_hash_based_offset(routing_metadata.flowID_hash, 0, migration_tbl_flowID_calculation, HASH_SIZE);
    register_write(flowReceiveID, routing_metadata.flowID_hash, 0);
    
}

action send_mig_ack() {
    // do nothing yetxx
    modify_field(_mig_flow_recv.flowhdr, MIG_TO_CONTROL);
    modify_field(_mig_flow_recv.subProtocol,MIGST_INITACK);
    // remove all headers and send to CPU
    //remove_header(networkinfo);
    remove_header(migrate_fwStateless);
    remove_header(migrate_fwStateful);
    remove_header(ethernet);
    remove_header(ipv4);
    remove_header(pktStats);
    remove_header(flowID);
    remove_header(icmp);
    remove_header(tcp);
    remove_header(udp);
    modify_field(standard_metadata.egress_spec, CPU_PORT);
    add_header(migrate_timing);
    modify_field(migrate_timing.ts, intrinsic_metadata.ingress_global_timestamp);
}


action send_pkt_to_sw(flowID) {
    modify_field(_mig_flow_recv.flowID, flowID);
}

action read_sid(sid) {
    modify_field(new_metadata.sid, sid);
}

action remove_ipv4_test() {
    remove_header(ipv4);
    remove_header(flowID);
    remove_header(ethernet);
}

action set_mig_protoc_zero_f() {
    modify_field(_mig_flow_recv.subProtocol, MIGST_SENDUPDATE);
    modify_field(_mig_flow_recv.subProtocol, 0x3c);
    modify_field(_mig_flow_recv.sequenceID, 1);
    register_write(flowReceiveID, routing_metadata.flowID_hash, _mig_flow_recv.sequenceID);
}

action plus_seqID() {
    add_to_field(_mig_flow_recv.sequenceID, 1);
    register_write(flowReceiveID, routing_metadata.flowID_hash, _mig_flow_recv.sequenceID);
}

action mig_packetful_flowID_write() {
    // calculate hash
    modify_field_with_hash_based_offset(packetCounter_metadata.flowHash, 0, mig_packetCounter_flowID_calculation, HASH_SIZE);
    register_write(reg_packetCounter, packetCounter_metadata.flowHash, migrate_packetCounter_values.nrPackets);
}

action clone_pass_update() {
    // test function for what works and what doesn't.
    modify_field(local_metadata.mirror_session, _mig_metadata.migSessionID);
    clone_i2e(_mig_metadata.migSessionID, mirror_fld_list);
}

action clone_pkt_set_hash() {
    add_header(_mig_flow_recv);
    modify_field_with_hash_based_offset(routing_metadata.flowID_hash, 0, migration_tbl_flowID_calculation, HASH_SIZE);
    register_read(_mig_flow_recv.migSessionID, flowSession, routing_metadata.flowID_hash);
    register_read(_mig_flow_recv.migSessionID, flowSession, routing_metadata.flowID_hash);
    
}
action mig_upd_pkt_egress(flowid) {
    // read info from database, probably it's not copied?
    modify_field_with_hash_based_offset(routing_metadata.flowID_hash, 0, migration_tbl_flowID_calculation, HASH_SIZE);
    add_header(networkinfo);
    modify_field(_mig_flow_recv.flowhdr, MIG_HDR);
    modify_field(_mig_flow_recv.flowID, flowid);
    modify_field(_mig_flow_recv.subProtocol,MIGST_SENDUPDATE);
    
    // fill network information
    modify_field(networkinfo.flowID, flowID.flowID);
    modify_field(networkinfo.migSrcIP,ipv4.srcAddr);
    modify_field(networkinfo.migDstIP,ipv4.dstAddr);
    modify_field(networkinfo.migSrcPort,port_metadata.srcPort);
    modify_field(networkinfo.migDstPort,port_metadata.dstPort);
    modify_field(networkinfo.migipProtocol,ipv4.protocol);

    // remove old headers    
    //remove_header(migrate_proxyStateless);
    remove_header(ethernet);
    remove_header(ipv4);
    remove_header(icmp);
    remove_header(tcp);
    remove_header(udp);
    remove_header(pktStats);
    remove_header(flowID);
    remove_header(migrate_packetCounter_values);
    remove_header(migrate_fwStateless);
    remove_header(migrate_fwStateful);
    register_read(_mig_metadata.migStatus, flowTable, routing_metadata.flowID_hash);
    register_read(_mig_flow_recv.sequenceID, flowReceiveID, routing_metadata.flowID_hash);
    add_to_field(_mig_flow_recv.sequenceID, 1);
    register_write(flowReceiveID, routing_metadata.flowID_hash, _mig_flow_recv.sequenceID);

    register_read(_mig_flow_recv.VNFID, flowVNFID, routing_metadata.flowID_hash);
    modify_field(local_metadata.mirror_session, _mig_metadata.migSessionID);

    bit_and(_mig_metadata.migdstsw, _mig_flow_recv.migSessionID, 0x0f);
    shift_right(_mig_metadata.migsrcsw, _mig_flow_recv.migSessionID, 4);
}
action send_forward_ack() {
    remove_header(ethernet);
    remove_header(ipv4);
    remove_header(icmp);
    remove_header(tcp);
    remove_header(udp);
    remove_header(pktStats);
    remove_header(flowID);
    remove_header(migrate_packetCounter_values);
    remove_header(migrate_fwStateless);
    remove_header(migrate_fwStateful);

    // store new status here is the fout
    modify_field(_mig_flow_recv.subProtocol, MIGST_FORWARD);
    register_write(flowTable, routing_metadata.flowID_hash, _mig_flow_recv.subProtocol);
    
    // send ack back
    modify_field(_mig_flow_recv.flowhdr, MIG_TO_CONTROL);
    remove_header(migrate_packetCounter_values);
    add_header(migrate_timing);
    modify_field(migrate_timing.ts, intrinsic_metadata.ingress_global_timestamp);
    modify_field(standard_metadata.egress_spec, CPU_PORT);

}


action flow_migrate_timing_process() {
    // remove all headers except:
    // - networkinfo
    // - mig_recvxxx
    remove_header(ethernet);
    remove_header(ipv4);
    remove_header(icmp);
    remove_header(tcp);
    remove_header(udp);
    remove_header(pktStats);
    remove_header(flowID);
    //remove_header(networkinfo);
    remove_header(migrate_packetCounter_values);
    remove_header(migrate_fwStateless);
    remove_header(migrate_fwStateful);
    modify_field_with_hash_based_offset(routing_metadata.flowID_hash, 0, migration_tbl_flowID_calculation, HASH_SIZE);
    modify_field(_mig_flow_recv.flowhdr, MIG_TO_CONTROL);
    modify_field(_mig_flow_recv.subProtocol, MIGST_REC_TIME);
    modify_field(standard_metadata.egress_spec, CPU_PORT);
    register_read(_mig_metadata.migStatus, flowTable, routing_metadata.flowID_hash);
    add_header(migrate_timing);
    modify_field(migrate_timing.ts, intrinsic_metadata.ingress_global_timestamp);
    
    //truncate(37); // length _mig_flow_recv, networkinfo + migrate_timing for now....
    // reset counter
    //modify_field_with_hash_based_offset(routing_metadata.flowID_hash, 0, migration_tbl_flowID_calculation, HASH_SIZE);
    //register_write(flowUpdateCounter, routing_metadata.flowID_hash, 0);
}

action readSendCPUpdate() {
    modify_field_with_hash_based_offset(routing_metadata.flowID_hash, 0, flowid_hash_routing_metadata_hash, HASH_SIZE);
    register_read(_mig_metadata.cpuUpdate, flowUpdateCounter, routing_metadata.flowID_hash);
    add_to_field(_mig_metadata.cpuUpdate, 1);
    register_write(flowUpdateCounter, routing_metadata.flowID_hash, _mig_metadata.cpuUpdate);
}
action ingress_flow_migrate_timing_process() {
    modify_field(_mig_flow_recv.flowhdr, MIG_TO_CONTROL);
    remove_header(migrate_packetCounter_values);
    add_header(migrate_timing);
    modify_field(migrate_timing.ts, intrinsic_metadata.ingress_global_timestamp);
    modify_field(standard_metadata.egress_spec, CPU_PORT);
    modify_field(_mig_flow_recv.subProtocol, MIGST_REC_TIME);
    //truncate(37); // length _mig_flow_recv, networkinfo + migrate_timing for now....
}

action clone_switch_time() {
    //clone_i2e(0xff, mirror_fld_list);
}

action migrate_forward_resubmit() {
    modify_field(_mig_metadata.stripMigHeaders, 0xff);
    recirculate(mig_forward_field_list);
    //drop();
}

action strip_mig_headers() {
    remove_header(_mig_flow_recv);
}

action forward_mig_pkt_set_sessid() {
    add_header(_mig_flow_recv);
    register_read(_mig_flow_recv.migSessionID, flowSession, routing_metadata.flowID_hash);
    bit_and(_mig_metadata.migdstsw, _mig_flow_recv.migSessionID, 0x0f);
    shift_right(_mig_metadata.migsrcsw, _mig_flow_recv.migSessionID, 4);
    modify_field(_mig_flow_recv.subProtocol, MIGST_FORWARD);
}
action forward_mig_pkt(flowid) {
    modify_field(_mig_flow_recv.flowhdr, MIG_HDR);
    modify_field(_mig_flow_recv.flowID,flowid);
    modify_field(_mig_flow_recv.subProtocol,MIGST_FORWARD);
    register_read(_mig_flow_recv.VNFID, flowVNFID, routing_metadata.flowID_hash);

    
}

action read_mig_sid() {
    bit_and(_mig_metadata.migdstsw, _mig_flow_recv.migSessionID, 0x0f);
    shift_right(_mig_metadata.migsrcsw, _mig_flow_recv.migSessionID, 4);
}
