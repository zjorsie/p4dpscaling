// example3: l3 forwarding 
#include "includes.p4"
#include "headers.p4"
#include "parsers.p4"
#include "registers.p4"
#include "field_lists.p4"
#include "actions.p4"
#include "tables.p4"

calculated_field ipv4.hdrChecksum  {
    update ipv4_checksum if(valid(ipv4));
}

calculated_field tcp.checksum {
    update tcp_checksum if(valid(tcp));
}


control ingress {
    if((standard_metadata.ingress_port == CPU_PORT) && ((valid(_ss_id) || (valid(_mig_flow_recv))))) {
        apply(plus_migration_table_ingress);
    }
    if(valid(flowID)) {
        // first, read a hash of the current flowID to a variable
        // calculate the hash and read the status from the database
        apply(calc_net_hash_normal_table);
    }
    else {
        apply(calc_net_hash_mig_table);
    }
    // read the switchID from the table
    apply(read_sid_table);

    if (standard_metadata.instance_type != PKT_INSTANCE_TYPE_NORMAL) {
        apply(strip_mig_headers_table);
    }
    if(ethernet.etherType == 0xffff && (!valid(_mig_flow_recv) && (!valid(_ss_id)))) {
        // this section handles the discovery process traffic
        if (standard_metadata.ingress_port == CPU_PORT){
            apply(handle_discovery_packet_table);
        }
        else {
            if (standard_metadata.ingress_port == 2) {
                // send packet with statistics back:
                apply(disc_pkt_to_cpu_tbl);
            }
            else {
                apply(disc_pkt_to_cpu_no_timing_tbl);
            }
            
        }
    }
    // else if(valid(_mig_flow_recv)) {
    //     apply(copy_to_cpu_table);
    // }
    
    else if (valid(_ss_id)) {
        apply(plus_migration_table);
        apply(read_ss_state_tbl);
        if (new_metadata.sid == 2) {
            // mig_dst (s2)
            
            if(_ss_m.state == PUTDOWN) {
                //putdown state
                apply(_ss_putdown_tbl);
                apply(send_ss_to_cpu_tbl);
                //forward to CPU
                
            }            
            else if (_ss_m.state == MIRROR){
                // do VNF and drop
                apply(apply_packetCounter_stateful_ss_tbl);
                apply(send_ss_mirror_to_cpu_tbl);
                //apply(drop_tbl);
            }
        }
        if ((new_metadata.sid == 4) || (new_metadata.sid == 1)){
            // dumb_forward to s2
            apply(forward_ss_tbl);
        }
    }
    else if(valid(_mig_flow_recv)){
        // do the migration counter:
        
        /* 
        This sequence does migration things.
        */
        // only thing this does now is changing states for the ss phase:

        if(standard_metadata.ingress_port == CPU_PORT) {
            apply(set_new_state_tbl);
        }
    }
    else {
        // read port metadata
        if(valid(ipv4)) {
            if (valid(tcp)) {
                apply(set_port_metadata_tcp_tbl);
            }
            else if (valid(udp)) {
                apply(set_port_metadata_udp_tbl);
            }
            else {
                apply(set_port_metadata_rest_tbl);
            }
        }
        
        // set the flowID if available
        if(port_metadata.set == 0xff) {
            apply(set_flowID_tbl);
            apply(recalculate_flowID_hash_after_set_flowID_tbl);
        }
        // read the flowID statistics and send to CPU if threshold overflowed
        if(new_metadata.init_without_flowID == 0xff) {
            apply(readPacketStats_table);
            if (int_pktstats.numPackets >= int_pktstats.threshold) {
                apply(sendPacketUpdate_table);
            }
        }
        apply(read_ss_state2_tbl);
        // do NF if:
        // - not cloned
        // - migration source and state == PICKUP
        // - migration destination and state == MIRROR

        if ((_ss_m.state == 0x0000) || ((new_metadata.sid == 3) && (_ss_m.state == PICKUP)) || ((new_metadata.sid == 2) && (_ss_m.state == MIRROR))) {
            apply(apply_packetCounter_stateful_tbl);
            apply(apply_packetCounter_stateful_flowID_tbl);
        }

        if ((new_metadata.sid == 2) && (_ss_m.state == MIRROR)) {     
                apply(drop_tbl2);
        }
        // if ((new_metadata.sid == 3) && (_ss_m.state == MIRROR)) {
        //     apply(forward_ss_append_tbl);

        // }
        if (((new_metadata.sid == 3) && (_ss_m.state == PICKUP)) || ((new_metadata.sid == 3) && (_ss_m.state == PICKUP))) {
            // do VNF and clone
                apply(clone_ss_tbl);
            // clone packet to s
        }

        //apply(test_clone);
        // make changes here. depending on the state of the flow, the vnf should be performed
        // furthermore, the packet (possibly clone) should be forwarded to the destination
        if ((_mig_metadata.migStatus == MIGST_INITSYNC) || (_mig_metadata.migStatus == MIGST_SENDUPDATE)) {
            
        }
        if (_mig_metadata.migStatus == MIGST_SENDUPDATE) {
            // send an update to the destination switch
            // find out if we are the migration source
            // then find out migration destination
            // then send a clone with layer _mig_metadata.sessionID (this clone will be forwarded to the correct switch)
            apply(clone_pass_update_table);
        }
        if (_mig_metadata.migStatus == MIGST_FORWARD) {
            // append a _mig_flow_recv header to the packet and fill all the (releant) values
            apply(forward_mig_pkt_set_sessid_tbl);
            apply(forward_mig_pkt_tbl);
            apply(route_mig_forward_flowID);
            // send a clone to the control plane:
            //apply(forward_clone_pkt);
        }
        else {
            // send to new destination
            if (valid(flowID)) {
                apply(route_flowID_tbl);
                if(standard_metadata.egress_spec != CPU_PORT) {
                    // only remove the flowID header when not sending things to the CPU
                    apply(remove_flowID_tbl);
                }
            }
            else {
                apply(send_to_cpu_tbl);
            }
        }
        /* flow states:
        1. normal. no migration and normal processing
        2. normal processing, send copy with updated state information to migration dest
        3. no processing, forward packet to destination.
        
        */
        // if state == 


    }
    // send digest if necessary
    apply(read_digest_send_tbl);
    if ((digest_pkt.send_digest != 0x0000) && (digest_pkt.enq_qdepth > 1)) {
        apply(send_digest_tbl);
    }
    apply(plus_total_table);
}
        
control egress {
    // for all cloned packets
    if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
        apply(ss_append_header_tbl);
    }

    //apply(monitor_read_data_tbl);
    //(store_digest_tbl);
    // if the new timestamp is larger than the one in the table; overwrite:
    if((valid(udp))|| ((queueing_metadata.deq_qdepth >= queueing_metadata.enq_qdepth) && (queueing_metadata.deq_qdepth != 0))) { 
        // if the queue is building
        // read alarm queue depth
        // read timedelta
        apply(monitor_read_data_tbl);        
        if (((true) || (queueing_metadata.deq_qdepth > digest_pkt.deq_qdepth) || (queueing_metadata.deq_timedelta > digest_pkt.deq_timedelta))) {
            apply(store_digest_tbl);
        }
    }
    // count packet to packet which has left the switch
    if(((new_metadata.sid == 3) && (valid(_ss_id) || valid(_mig_flow_recv)))) {
        
    }
    if (((new_metadata.sid == 3) && (valid(_ss_id) || valid(_mig_flow_recv))) ||((standard_metadata.egress_spec != CPU_PORT) && ((valid(_ss_id) || (valid(_mig_flow_recv))))) ) {
        
    }
    if((standard_metadata.egress_spec != CPU_PORT) && ((valid(_ss_id) || (valid(_mig_flow_recv))))) {
        
    }
}