def switchRules(s,s_type):
    installRule = {}
    if s_type == str('switch'):
        installRule["default_action"] = True
        installRule["table_name"] = "send_digest_tbl"
        installRule["action_name"] = "send_digest"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "store_digest_tbl"
        installRule["action_name"] = "store_digest"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "read_digest_send_tbl"
        installRule["action_name"] = "read_digest_send"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "disc_pkt_to_cpu_tbl"
        installRule["action_name"] = "disc_pkt_to_cpu"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)     
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "disc_pkt_to_cpu_no_timing_tbl"
        installRule["action_name"] = "disc_pkt_to_cpu_no_timing"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)  
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "handle_discovery_packet_table"
        installRule["action_name"] = "handle_discovery_packet"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "plus_total_table"
        installRule["action_name"] = "plus_total"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "apply_proxy_stateless_tbl"
        installRule["action_name"] = "_nop"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "apply_packetCounter_stateful_tbl"
        installRule["action_name"] = "_nop"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "apply_packetCounter_stateful_flowID_tbl"
        installRule["action_name"] = "_nop"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "route_flowID_tbl"
        installRule["action_name"] = "send_to_cpu"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "remove_flowID_tbl"
        installRule["action_name"] = "_nop"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "set_port_metadata_tcp_tbl"
        installRule["action_name"] = "set_port_metadata_tcp"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "set_port_metadata_udp_tbl"
        installRule["action_name"] = "set_port_metadata_udp"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "set_flowID_tbl"
        installRule["action_name"] = "_nop"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "set_port_metadata_rest_tbl"
        installRule["action_name"] = "set_port_metadata_rest"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "send_to_cpu_tbl"
        installRule["action_name"] = "send_to_cpu"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "calc_net_hash_normal_table"
        installRule["action_name"] = "calc_net_hash_normal"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "calc_net_hash_mig_table"
        installRule["action_name"] = "calc_net_hash_mig"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "write_flowID_to_regs_table"
        installRule["action_name"] = "write_flowID_to_regs"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "add_packetCounter_header_table"
        installRule["action_name"] = "add_packetCounter_header"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "update_packetCounter_header_table"
        installRule["action_name"] = "add_packetCounter_header"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "send_mig_ack_table"
        installRule["action_name"] = "send_mig_ack"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "read_seqID_from_reg_table"
        installRule["action_name"] = "read_seqID_from_reg"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "store_seqID_to_reg_table"
        installRule["action_name"] = "store_seqID_to_reg"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "add_proxyStateless_header_table"
        installRule["action_name"] = "add_proxyStateless_header"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "route_mig_flowID"
        installRule["action_name"] = "route_flowID"
        installRule["match_fields"] = {}
        installRule["action_params"] = {'outPort': 511}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "read_sid_table"
        installRule["action_name"] = "read_sid"
        installRule["match_fields"] = {}
        installRule["action_params"] = {'sid': int(s.swNum)}
        s.defaultRules.append(installRule)

        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "set_mig_protoc_zero_f_table"
        installRule["action_name"] = "set_mig_protoc_zero_f"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "plus_seqID_table"
        installRule["action_name"] = "plus_seqID"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "recalculate_flowID_hash_after_set_flowID_tbl"
        installRule["action_name"] = "recalculate_flowID_hash_after_set_flowID"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "add_packetCounter_header_table"
        installRule["action_name"] = "add_packetCounter_header"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "mig_packetful_flowID_write_tbl"
        installRule["action_name"] = "mig_packetful_flowID_write"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "clone_pass_update_table"
        installRule["action_name"] = "clone_pass_update"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "mig_upd_pkt_egress_table"
        installRule["action_name"] = "_nop"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = False
        installRule["table_name"] = "mig_upd_pkt_egress_table"
        installRule["action_name"] = "mig_upd_pkt_egress"
        installRule["match_fields"] = {
            '_mig_flow_recv.migSessionID': 0xff
        }
        installRule["action_params"] = {
            'flowid': 0xffff0000
        }
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "clone_pkt_set_hash_table"
        installRule["action_name"] = "clone_pkt_set_hash"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "egress_set_port_metadata_tcp_tbl"
        installRule["action_name"] = "set_port_metadata_tcp"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "egress_set_port_metadata_udp_tbl"
        installRule["action_name"] = "set_port_metadata_udp"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "egress_set_port_metadata_rest_tbl"
        installRule["action_name"] = "set_port_metadata_rest"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "flow_migrate_timing_process_table"
        installRule["action_name"] = "flow_migrate_timing_process"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "clone_switch_time_table"
        installRule["action_name"] = "clone_switch_time"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        # installRule = {}
        # installRule["default_action"] = True
        # installRule["table_name"] = "add_migrate_timing_header_forward_CPU_tbl"
        # installRule["action_name"] = "add_migrate_timing_header_forward_CPU"
        # installRule["match_fields"] = {}
        # installRule["action_params"] = {}
        # s.defaultRules.append(installRule) 
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "send_mig_ack_forward_state_tbl"
        installRule["action_name"] = "send_forward_ack"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "strip_mig_headers_table"
        installRule["action_name"] = "strip_mig_headers"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "forward_mig_pkt_tbl"
        installRule["action_name"] = "_nop"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = False
        installRule["table_name"] = "forward_mig_pkt_tbl"
        installRule["action_name"] = "forward_mig_pkt"
        installRule["match_fields"] = {
            '_mig_flow_recv.migSessionID': 0xff,
        }
        installRule["action_params"] = {
            'flowid': 0xffff0000,
        }
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "forward_mig_pkt_set_sessid_tbl"
        installRule["action_name"] = "forward_mig_pkt_set_sessid"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "route_mig_forward_flowID"
        installRule["action_name"] = "route_flowID"
        installRule["match_fields"] = {}
        installRule["action_params"] = {'outPort': 511}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = False
        installRule["table_name"] = "route_mig_forward_flowID"
        installRule["action_name"] = "route_flowID"
        installRule["match_fields"] = {'_mig_flow_recv.flowID': 0xffff0000}
        installRule["action_params"] = {'outPort': int(255)}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "migrate_forward_resubmit_table"
        installRule["action_name"] = "migrate_forward_resubmit"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "sendPacketUpdate_table"
        installRule["action_name"] = "sendPacketUpdate"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "read_mig_sid_table"
        installRule["action_name"] = "read_mig_sid"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "readPacketStats_table"
        installRule["action_name"] = "readPacketStats"
        installRule["match_fields"] = {}
        installRule["action_params"] = {"THRESHOLD": 10}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "monitor_read_data_tbl"
        installRule["action_name"] = "monitor_read_data"
        installRule["match_fields"] = {}
        installRule["action_params"] =  {
                                            "dequeuedepthlimit": 20,
                                            "timedelta_max": 50 * 1000000  # 50ms
        
                                        }
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "forward_time_info_to_cpu_table"
        installRule["action_name"] = "ingress_flow_migrate_timing_process"
        installRule["match_fields"] = {}
        installRule["action_params"] =  {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "plus_migration_table"
        installRule["action_name"] = "plus_migration"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)

        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "set_carrystate_1"
        installRule["action_name"] = "set_carry_state_e"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)
        installRule = {}
        installRule["default_action"] = True
        installRule["table_name"] = "set_carrystate_2"
        installRule["action_name"] = "set_carry_state"
        installRule["match_fields"] = {}
        installRule["action_params"] = {}
        s.defaultRules.append(installRule)

        
        # installRule = {}
        # installRule["default_action"] = True
        # installRule["table_name"] = "send_mig_ack_table"
        # installRule["action_name"] = "send_mig_ack"
        # installRule["match_fields"] = {}
        # installRule["action_params"] =  {}
        # s.defaultRules.append(installRule)
        # installRule = {}
        # installRule["default_action"] = True
        # installRule["table_name"] = "readSendCPUpdate_tbl"
        # installRule["action_name"] = "readSendCPUpdate"
        # installRule["match_fields"] = {}
        # installRule["action_params"] =  {}
        # s.defaultRules.append(installRule)
        # installRule = {}
        # installRule["default_action"] = True
        # installRule["table_name"] = "egress_read_migStatus"
        # installRule["action_name"] = "calc_net_hash_mig"
        # installRule["match_fields"] = {}
        # installRule["action_params"] =  {}
        # s.defaultRules.append(installRule)   
