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
    if(ethernet.etherType == 0xffff && (!valid(_mig_flow_recv))) {
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
    else if(valid(_mig_flow_recv)){
        // do the migration counter:
        
        /* 
        This sequence does migration things.
        */
        apply(read_mig_sid_table);
        if((new_metadata.sid == _mig_metadata.migdstsw) || (new_metadata.sid == _mig_metadata.migsrcsw)) {
            apply(plus_migration_table);
        }
        if(new_metadata.sid == _mig_metadata.migdstsw) {
            // read the seqID from the register
            apply(read_seqID_from_reg_table);
            
            // only do something if the sequence ID is larger than before
            if (_mig_flow_recv.subProtocol == MIGST_SENDUPDATE) {
            // only import values if the sequence number is not out of date.. 
            // both 0x0f and 0xf0 don't require processing, so just accept the latest packet and do not count the rest
            // TODO kan misschien iets bouwen voor counting states. deze mogen wel wordne meegenomen...
                if((_mig_metadata.regSeqID < _mig_flow_recv.sequenceID) || (_mig_flow_recv.sequenceID == INITMIGID)) {
                    // when receiving inital sync packet
                    // or when receiving an update packet..
                    if(_mig_flow_recv.VNFID == VNF_PROXYLESS) {
                        // do things to import proxyStateless variables
                        // it's proxystateless, so don't import any state values

                    }
                    else if(_mig_flow_recv.VNFID == VNF_PACKETFUL) {
                        // do things to import packetCounter
                        apply(mig_packetful_flowID_write_tbl);

                    }
                    else if(_mig_flow_recv.VNFID == VNF_FWLESS) {
                        // do things to import fwStateless

                    }
                    else if(_mig_flow_recv.VNFID == VNF_FWFUL) {
                        // do things to import fwStateful

                    }
                    // send timing to the control plane
                    if (_mig_flow_recv.sequenceID != INITMIGID) {
                        //apply(forward_time_info_to_cpu_table);
                    }                    
                }
                apply(store_seqID_to_reg_table);
                // send an initial upgrade to host
                if (_mig_flow_recv.sequenceID == INITMIGID && _mig_flow_recv.flowhdr != MIG_TO_CONTROL) {
                    // send an ack back to the src sw
                    apply(send_mig_ack_table);
                
                }
                else if (_mig_flow_recv.sequenceID != INITMIGID && _mig_flow_recv.flowhdr != MIG_TO_CONTROL) {
                    // send timing information to CPU
                    //apply(flow_migrate_timing_process_table);
                }
            }
            else if (_mig_flow_recv.subProtocol == MIGST_FORWARD) {
                // this routine is for packets in the forward phase
                // assuming resubmit works:
                /*
                    - set metadata flag that indicates about what headers have to be stripped
                    - resubmit
                    - drop this packet
                */
                // basically, remove all the migration headers and perform the thing (does recirculate work?)
                if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL) {
                    apply(migrate_forward_resubmit_table);
                }
                
                
            }
            else {
                // drop
                //apply(drop_tbl);
            }
        }
        else {
            // either the migration source or another forwarding switch.....
            // if it is an migration packet and this switch is the source
            if (new_metadata.sid == _mig_metadata.migsrcsw && standard_metadata.ingress_port == CPU_PORT) {
                // if this is the first in the sequence:
                // write_flowid_to_regs_table writes the current migStatus, migSessionID, and VNFID to regs
                apply(write_flowID_to_regs_table);

                if (_mig_flow_recv.subProtocol == MIGST_INITSYNC) {
                    // write the state/session information to the registers for new packets
                    // first packet for migration is received (from controller)
                    
                    // add specific values for VNFs
                    // see libs/dbConnect for python side of the code.

                    if (_mig_flow_recv.VNFID == VNF_PROXYLESS) {
                        // add the vnf proxystateless header
                        // does nothing as the vnf is stateless.
                        apply(add_proxyStateless_header_table);
                    }
                    else if (_mig_flow_recv.VNFID == VNF_PACKETFUL) {
                        // add the vnf packetCounter header
                        apply(add_packetCounter_header_table);
                        // send this to the destination switch.
                    }
                    else if (_mig_flow_recv.VNFID == VNF_FWLESS) {
                        // add the vnf firewallstateless header
                    }
                    else if (_mig_flow_recv.VNFID == VNF_FWFUL) {
                        // add the vnf firewallstatefull header
                    }
                    // now the values are appended. Send the packet to the destination:
                    // change the protocol ID to 0x0f and send to CPU
                    apply(set_mig_protoc_zero_f_table);
                    // append one to the sequenceID:
                    //apply(plus_seqID_table);
                }
                if (_mig_flow_recv.subProtocol == MIGST_INITFORWARD) {
                    // send a packet back to the control plane to indicate this action has been done.
                    apply(send_mig_ack_forward_state_tbl);
                }
            }
            // forward packet to destination switch with given flowID
            if (_mig_flow_recv.flowhdr != MIG_TO_CONTROL) {
                apply(route_mig_flowID);
            }
            
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
        //apply(test_clone);
        // make changes here. depending on the state of the flow, the vnf should be performed
        // furthermore, the packet (possibly clone) should be forwarded to the destination
        if ((_mig_metadata.migStatus == MIGST_INITSYNC) || (_mig_metadata.migStatus == MIGST_SENDUPDATE)) {
            apply(apply_proxy_stateless_tbl);  
            apply(apply_packetCounter_stateful_tbl);
            apply(apply_packetCounter_stateful_flowID_tbl);
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
        // if the packet is cloned from ingress (a migration scheme state update)
        if(valid(ipv4)) {
            if (valid(tcp)) {
                apply(egress_set_port_metadata_tcp_tbl);
            }
            else if (valid(udp)) {
                apply(egress_set_port_metadata_udp_tbl);
            }
            else {
                apply(egress_set_port_metadata_rest_tbl);
            }
        }
        apply(clone_pkt_set_hash_table);
        apply(mig_upd_pkt_egress_table);
        apply(clone_switch_time_table);
        if (_mig_flow_recv.VNFID == VNF_PROXYLESS) {
            // add the vnf proxystateless header
            // does nothing as the vnf is stateless.
        }
        else if (_mig_flow_recv.VNFID == VNF_PACKETFUL) {
            // add the vnf packetCounter header
            apply(update_packetCounter_header_table);
            // send this to the destination switch.
        }
        else if (_mig_flow_recv.VNFID == VNF_FWLESS) {
            // add the vnf firewallstateless header
        }
        else if (_mig_flow_recv.VNFID == VNF_FWFUL) {
            // add the vnf firewallstatefull header
        }
    }
    if(standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE) {
        // for notifications to the switch about the state updates
        //apply(flow_migrate_timing_process_table);
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
    if(valid(_mig_flow_recv) && standard_metadata.egress_spec != CPU_PORT) {
        //apply(plus_migration_table);
    }
}