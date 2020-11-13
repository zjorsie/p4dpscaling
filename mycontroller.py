#!/usr/bin/env python2
import argparse
import socket
import grpc
import os
import sys
import json
import threading
import random
from Queue import Queue
import dpkt
import networkx as nx
import libs.netGraph as netGraph
import libs.monitoringStats as pktMon
import libs.appServices as appServices
import libs.dbConnect as dbConnect
from libs.defaultRules import switchRules
import libs.flowHandler as flowHandler 
import pexpect
import libs.flowMonitor as flowMonitor
import libs.vnfHandler as vnfHandler
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from libs.lockGraphs import lock

import time

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import libs.p4runtime_lib.bmv2 as p4runtime_lib_bmv2
import libs.switchFinder as switchFinder
import libs.p4runtime_lib.helper as p4runtime_lib_helper
import libs.p4runtime_lib.simple_controller as simple_controller


#NATDict = {}
class ConfException(Exception):
    pass


    
def printGrpcError(e):
    print("gRPC Error:")
    print(e)
    #status_code = e.code()
    #print "(%s)" % status_code.name,
    #traceback = sys.exc_info()[2]
    #print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def addSwitch(name,address,device_id,proto_dump_file,p4info_file_path, toFlowID):
    # define switch
    queueDepth = 10000
    controlPlaneDelay = 0.5 # s
    if name == 's1':
        queueRate = 9999
        thriftPort = 9090
    if name == 's2':
        queueRate = 250
        thriftPort = 9091
    if name == 's3':
        queueRate = 250
        thriftPort = 9092
    if name == 's4':
        queueRate = 9999
        thriftPort = 9093
    s = p4runtime_lib_bmv2.Bmv2SwitchConnection(name=name,address=address,device_id=device_id,proto_dump_file=proto_dump_file,p4info_file_path=p4info_file_path, toFlowID=toFlowID, queueDepth=queueDepth, queueRate=queueRate, thriftPort=thriftPort, controlPlaneDelay=controlPlaneDelay)
    # log print something
    print("switch added! " + str(s.address))
    return s

def switchReachTopo():
    # this function will take care of installing all rules for the 'route_mig_flowID' table.
    # it will be performed once every time. It will, for each swich, calculate paths to all switches and will install a port
    # static flowID's will be used to reduce overhead.    

    # installRule["default_action"] = True
    #     installRule["table_name"] = "send_pkt_to_sw_table"
    #     installRule["action_name"] = "_nop"
    #     installRule["match_fields"] = {}
    #     installRule["action_params"] = {}
    for srcSw in switchFinder.allSwitches:
        for dstSw in switchFinder.allSwitches:
            if dstSw.stop == True:
                return
            if srcSw.name != dstSw.name:
                # get the output port of the shortest path on the source node.
                outPort = netGraph.getOutportToDst(srcSw.name, dstSw.name)
                installRules = []
                if outPort >= 0:
                    # we have received a valid output port
                    #print "Switch %s is reachable from %s via port %d with flowID %s" %(dstSw.name, srcSw.name, outPort, dstSw.toFlowID)

                    # TODO Do probably a check if some other rule already exists for this flowID on the switch. Will cause errors if it does.
                    # install a rule.
                    
                    installRule = {
                        "table_name": "route_mig_flowID",
                        "action_name": "route_flowID",
                        "match_fields": {"_mig_flow_recv.flowID":dstSw.toFlowID},
                        "action_params": {"outPort": outPort},
                        "default_action": False,
                    }
                    installRules.append(installRule)
                    installRule = {
                        "table_name": "route_mig_forward_flowID",
                        "action_name": "route_flowID",
                        "match_fields": {"_mig_flow_recv.flowID":dstSw.toFlowID},
                        "action_params": {"outPort": outPort},
                        "default_action": False,
                    }
                    installRules.append(installRule)
                installRule = {
                    "table_name": "mig_upd_pkt_egress_table",
                    "action_name": "mig_upd_pkt_egress",
                    "match_fields": {"_mig_flow_recv.migSessionID":int(srcSw.swNum * 16 + dstSw.swNum)},
                    "action_params": {"flowid": dstSw.toFlowID},
                    "default_action": False,
                }
                installRules.append(installRule)
                installRule = {
                    "table_name": "forward_mig_pkt_tbl",
                    "action_name": "forward_mig_pkt",
                    "match_fields": {"_mig_flow_recv.migSessionID":int(srcSw.swNum * 16 + dstSw.swNum)},
                    "action_params": {"flowid": dstSw.toFlowID},
                    "default_action": False,
                }
                installRules.append(installRule)
                
                srcSw.installRulesOnSwitch(installRules)

    time.sleep(1)
    if dstSw.stop == True:
            return

def send_disc_topology():
    # algorithm works as follows:
    # first, every port in history active ports are checked
    
    
    pkt = dpkt.ethernet.Ethernet()
    pkt.src = '\377\377\377\377\377\377'
    pkt.dst = '\377\377\377\377\377\377'
    pkt.type = 0xffff
    
    i = 0
    while True:
        for s in switchFinder.allSwitches:
            if s.stop == True:
                return
            # start by removing all host connections from the connection check; these won't be used
            for port in netGraph.getNeighborTypePorts(s.name, 'host'):
                if port in s.activePorts.keys():
                    del s.activePorts[port]
                if port in s.inactivePorts:
                    s.inactivePorts.remove(port)

            # send discovery to all known active ports
            for port in s.activePorts.keys():
                sendDiscpkt(s,port)
                if s.activePorts[port] < 3:
                    s.activePorts[port] += 1
                else:
                    del s.activePorts[port]
                     # Add the port to the inactive port array. It will still be monitored, with a lower frequency.
                    s.inactivePorts.append(port)
                    # Remove link from netGraph
                    dst = netGraph.getNeighborSwitchbyPort(s.name, port)
                    if dst != None:
                        netGraph.delLink(s.name,dst)
                   
                
            # each 5 seconds, try to do broadcast to higher port numbers. However, do not check on ports where clients are connected.
            if i == 0:
                checkPorts = [0] + s.activePorts.keys() + s.inactivePorts
                for port in range(1,int(max(checkPorts) + 10)):
                    if port not in s.activePorts:
                        sendDiscpkt(s,port)
        
        time.sleep(0.5)
        if i == 10:
            i = 0
            # time.sleep(1000)
        else:
            i += 1

def doRandomMigration():
    """This loop performs a random migration of a source switch to a destination switch. This fuction simulates a 'scaling neccessity' that is detected by the system, and thus will fix some things""" 
    pass
    # migration:
    # info: which switchs overloads.
    # find out: which flows are overloading the system
    # find out: is there a fix without spinning up new systems (load balance flows)
    #   for several flows:
        # can the load be balanced to other switches in such a way that the load becomes low enough on this switch?
    # else:
    # a new service has to be initialized
        # on which switch should it be done?
        # for each service:
            # find each switch possibility
            # do the one with the shortest path to the next service, while obiding the assumptions (only one VNF per switch)
    # find out: 
    #   which service should be scaled

    # todo:
    # implement downscaling
    # see if load balancing can happen with a switch less
    #   probably something with maximum added latencyexi 


def sendDiscpkt(s,port):
    pkt = dpkt.ethernet.Ethernet()
    pkt.src = '\377\377\377\377\377\377'
    pkt.dst = '\377\377\377\377\377\377'
    pkt.type = 0xffff
    pkt.data = '\000' + str(unichr(port)) +  s.name
    packet_out_req = p4runtime_pb2.PacketOut()
    
    # send a disc packet to the destination
    packet_out_req.payload = bytes(pkt)
    req = p4runtime_pb2.StreamMessageRequest()
    req.packet.CopyFrom(packet_out_req)
    s.stream_out_q.put(req)

def isOpen(ip,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((ip,port))
    if result == 0:
        return True
    else:
        return False

def removeOldRules():
    # only do this for the network switches, assume all rules have to be kept for the applications (e.g. nat/tunneling)
    #print "the removeoldRules funcitn does not work"
    return
    while True:
        for s in switchFinder.allSwitches:
            for installedRule in s.installedRules:
                for x in s.installedRules[installedRule]:
                    if time.time() - x["ts"] > 10:
                        pass
                        #s.removeRule(x)
        if s.stop == True:
            break
        time.sleep(0.5)

def main(p4, scale):
    dbConnect.createEmptyDB()
    # run monitor settings for port duplication:
    
        #     ap4['version'] = int(args.ap4)
        # ap4['filebuild'] = ap4file + p4p4ext
        # ap4['p4buildp4info'] = ap4file + p4infoext
        # ap4['p4buildjson'] = ap4file + p4jsonext
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib_helper.P4InfoHelper(p4['p4buildp4info'])

    topo_thread = threading.Thread(target=send_disc_topology, args=())
    remove_rule_thread = threading.Thread(target=removeOldRules, args=())
    migSWRuleInstall_thread = threading.Thread(target=switchReachTopo, args=())
    pktMon.initpktMon()
    # start and initalize the databases
    

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        device_id = 0
        if args.doCPSync == True:
            addSwitch(name='s1',address='localhost:50051',device_id=device_id,proto_dump_file='/home/nijhuis/p4runtime-code/logs/grpc/s1-p4runtime-requests.txt', p4info_file_path=p4['p4buildp4info'], toFlowID=0xffff0000)
            device_id += 1
            addSwitch(name='s2',address='localhost:50052',device_id=device_id,proto_dump_file='/home/nijhuis/p4runtime-code/logs/grpc/s2-p4runtime-requests.txt', p4info_file_path=p4['p4buildp4info'], toFlowID=0xffff0000)
            device_id += 1
            addSwitch(name='s3',address='localhost:50053',device_id=device_id,proto_dump_file='/home/nijhuis/p4runtime-code/logs/grpc/s3-p4runtime-requests.txt', p4info_file_path=p4['p4buildp4info'], toFlowID=0xffff0000)
            device_id += 1
            addSwitch(name='s4',address='localhost:50054',device_id=device_id,proto_dump_file='/home/nijhuis/p4runtime-code/logs/grpc/s4-p4runtime-requests.txt', p4info_file_path=p4['p4buildp4info'], toFlowID=0xffff0000)
            device_id += 1
        else:
            addSwitch(name='s1',address='localhost:50051',device_id=device_id,proto_dump_file='/home/nijhuis/p4runtime-code/logs/grpc/s1-p4runtime-requests.txt', p4info_file_path=p4['p4buildp4info'], toFlowID=0xffff1111)
            device_id += 1
            addSwitch(name='s2',address='localhost:50052',device_id=device_id,proto_dump_file='/home/nijhuis/p4runtime-code/logs/grpc/s2-p4runtime-requests.txt', p4info_file_path=p4['p4buildp4info'], toFlowID=0xffff2222)
            device_id += 1
            addSwitch(name='s3',address='localhost:50053',device_id=device_id,proto_dump_file='/home/nijhuis/p4runtime-code/logs/grpc/s3-p4runtime-requests.txt', p4info_file_path=p4['p4buildp4info'], toFlowID=0xffff3333)
            device_id += 1
            addSwitch(name='s4',address='localhost:50054',device_id=device_id,proto_dump_file='/home/nijhuis/p4runtime-code/logs/grpc/s4-p4runtime-requests.txt', p4info_file_path=p4['p4buildp4info'], toFlowID=0xffff4444)
            device_id += 1
        
        # define services:
        services = ['general', 'proxyStateless', 'packetCounter', 'fwStateless', 'fwStateful']
        # program switches
        for s in switchFinder.allSwitches:
            netGraph.addHost(s.name,'switch')
            pktMon.addpktSwitch(s.name, 'switch', services)
            
            s.SetForwardingPipelineConfig(p4info=s.p4info_helper.p4info, bmv2_json_file_path=p4['p4buildjson'])

            # generate and install table rules
            switchRules(s, 'switch')
            s.installRulesOnSwitch(s.defaultRules)   
            print "I have installed all default rules"    
                    
            # enable digest for all digest things in the code
            for digest_id in p4info_helper.get_all_id('digests'):
                s.StreamDigestMessages(digest_id)
            if args.doCPSync == True:
                print 'doing custom dingen'
                install_monitoring_rules(sw=s, cpSync = True)
            else:
                install_monitoring_rules(sw=s, cpSync = False)
        
        # after switch configuration, start topology thread: 
        topo_thread.start()
        remove_rule_thread.start()
        migSWRuleInstall_thread.start()
        
        vnfHandler.startProxyService(dstSwName='s3')
        vnfHandler.startPacketCounter(dstSwName='s3')
        vnfHandler.startPacketCounter(dstSwName='s2')
        timeDiv = 0
        while True:
            tStart = time.time()
            try:
                #netGraph.printGraph('network.png')
                # sometimes crashes....
                pass
            except:
                pass
            #pktMon.printInfo()
            for s in switchFinder.allSwitches:
                s.printTables()
                if s.stop == True:
                    break
            # if threads crash: restart them
            if not topo_thread.isAlive():
                topo_thread = threading.Thread(target=send_disc_topology, args=())
                topo_thread.start()
            if not remove_rule_thread.isAlive():
                remove_rule_thread = threading.Thread(target=removeOldRules, args=())
                remove_rule_thread.start()
            if not migSWRuleInstall_thread.isAlive():
                migSWRuleInstall_thread = threading.Thread(target=switchReachTopo, args=())
                migSWRuleInstall_thread.start()
            tLoop = time.time() - tStart
            #print 'Loop time: %f' % tLoop
            
                    
            time.sleep(1)

            
    except KeyboardInterrupt:
        print "Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)
        print "Shutting down."
    except Exception as e:
        print "Een rare exception is gebeurd."
        print e
        print "Shutting down"
    print ('')
    print ('')
    print ('')
    print ('')
    print ('')
    print('REDIE!')
    
    for s in switchFinder.allSwitches:
        s.shutdown()
    if topo_thread.isAlive():
        topo_thread.join()
    print "killed topo thread"
    if remove_rule_thread.isAlive():
        remove_rule_thread.join()
    print "killed rule remove thread"
    if migSWRuleInstall_thread.isAlive():
        migSWRuleInstall_thread.join()
    print "killed migration SW rule installer thread"
    # result = os.system("mergecap -w logs/combined.pcap logs/*.pcap")
    # if result != 0:
    #         print("An error occured, quitting")
    # else:
    #     print("Pcaps are combined and stored in logs/combined.pcap")
    
    dbConnect.closeAllDBConns()
    print("everything is closed. Exiting...")
    exit()

def install_monitoring_rules(sw, cpSync=False): 
    if sw.name == 's1':
        sessions = [0x12, 0x13, 0x14, 0xff]
        ports = [2, 3, 3, 255]
    if sw.name == 's2':
        sessions = [0x21, 0x23, 0x24, 0xff]
        ports = [1, 2, 2, 255]
    if sw.name == 's3':
        sessions = [0x31, 0x32, 0x34, 0xff]
        ports = [1, 1, 2, 255]
    if sw.name == 's4':
        sessions = [0x41, 0x42, 0x43, 0xff]
        ports = [2, 3, 2, 255]

    if cpSync == True:
        ports = [255, 255, 255, 255]

    if not isOpen('127.0.0.1', sw.thriftPort):
        print "Port %s is not open. Switch is probably not running" % str(sw.thriftPort)
        print "exiting"
        exit

    child = pexpect.spawn('simple_switch_CLI --thrift-port %s' % str(sw.thriftPort))
    for i in range(len(sessions)):
        child.expect('RuntimeCmd:')
        child.sendline('mirroring_add %s %s' % (int(sessions[i]), int(ports[i])))
    child.expect('RuntimeCmd:')
    child.sendline('set_queue_depth %i' % int(sw.queueDepth))
    child.expect('RuntimeCmd:')
    child.sendline('set_queue_rate %i' % int(sw.queueRate))
    child.expect('RuntimeCmd:')
    child.sendline('exit')

def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-p4', help='P4 version for network program', required = False, default='14', dest = 'p4', type = int)
    parser.add_argument('-p4folder', help = "Folder where p4 program is located", required = False, default='p4source-dpsync', dest = 'p4folder', type = str)
    parser.add_argument('-p4file', help = "P4 file for compilation", required = False, default = 'firewall', dest = 'p4file', type = str)
    parser.add_argument('-wb', '--with-build', help = "Build all p4 programs", required = False, action='store_true', dest = 'withbuild')
    parser.add_argument('--scale', help="Do scaling experiment", action='store_true', dest='scale')
    parser.add_argument('--cpsync', '-cps', help="Do synchronization over the control plane", action='store_true', dest='doCPSync')
 
    return parser.parse_args()

def compileP4(p4dict):
    
    if not os.path.isfile(p4dict['filebuild']):
        print ("File %s does not exist" % (p4dict['filebuild']))
        quit()
    else:
        # compile
        result = os.system("p4c-bm2-ss --p4v %i --p4runtime-files %s -o %s %s" % (p4dict['version'] , p4dict['p4buildp4info'], p4dict['p4buildjson'], p4dict['filebuild']))
        if result != 0:
            print("An error occured during P4 compilation, quitting")
            quit()
        print("%s built succesfully!" %(p4dict['filebuild']))

def migrateFlowSwitch(origSw, dstSw, p4info_file_path=None, bmv2_json_file_path=None, service=None):
    # TODO
    # rewrite this function.
    # - enable code on new switch
    # - copy installed rules from src to dst       

    return '-1'


if __name__ == '__main__':
    args = get_args()

    p4infoext = ".p4.p4info.txt"
    p4jsonext = ".json"
    p4p4ext = ".p4"
    
    p4file = str(args.p4folder) + '/' + str(args.p4file) 
    p4 = {}
    p4['version'] = int(args.p4)
    p4['filebuild'] = p4file + p4p4ext
    p4['p4buildp4info'] = p4file + p4infoext
    p4['p4buildjson'] = p4file + p4jsonext

    if args.withbuild:
        compileP4(p4)
    
    # now run p4program    
    # check if all files exists:
    for filename in p4:
        file = p4[filename]
        if type(file) != int:
            if not os.path.isfile(file) :
                print ("File %s does not exist" % (file))
                quit()

    main(p4, args.scale) #args.p4info, args.bmv2_json)