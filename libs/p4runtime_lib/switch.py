# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# for division with floats
from __future__ import division
from Queue import Queue
from abc import abstractmethod
from datetime import datetime
import dpkt
import threading
import grpc
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from p4.tmp import p4config_pb2
import time
import re
import struct
import socket
import cProfile,pstats, io
import base64
from time import sleep
from time import time
import google.protobuf.json_format
import json
import libs.monitoringStats as pktMon
import libs.appServices as appServices
import libs.flowHandler as flowHandler
import libs.dbConnect as dbConnect
import libs.flowMonitor as flowMonitor
import copy
import random
import binascii
from array import array
import bitstring
import libs.switchFinder as switchFinder
from libs.netFlows import getHash
from libs.netFlows import updateHash
from libs.netFlows import removeHash


def convert_number_to_weird(n):
    b = bytearray.fromhex(format(n, 'x'))
    b.reverse()
    print int(binascii.hexlify(b), 16)


MSG_LOG_MAX_LEN = 1024
DEBUGGER = False

import libs.controlPacket as controlPacket
import libs.netGraph as netGraph
from libs.controlPacket import print_mac_addr

#import p4runtime_lib.bmv2 as p4runtime_lib_bmv2
import helper as p4runtime_lib_helper
#import p4runtime_lib.simple_controller as simple_controller
# List of all active connections
# changed to switchFinder.py!!!
#connections = []





def findRoute(src,dst):
    path = []
    # calculate the total path service by service. If none exists, path between src and dst is calculated.
    path = netGraph.getShortestPath(src,dst)
    if path == None:
        print "2iets foutgegaan in berekenen route between %s and %s" % (src,dst)
        return []
    return path

def pathFindFirstSwitch(path):
    i = 0
    while netGraph.getHostAttr(path[i],"type") != "switch": 
        i += 1
    return path[i] 

    
def pathFindLastSwitch(path):
    i = len(path) - 1

    while netGraph.getHostAttr(path[i],"type") != "switch": 
        i -= 1
    return path[i]




class SwitchConnection(object):

    def __init__(self, name=None, address="127.0.0.1:50051", device_id=0,p4info_file_path=None, 
                 proto_dump_file=None, p4configjson = None, toFlowID = 0xffff0000, queueDepth=1000, queueRate=1000, thriftPort=9090, controlPlaneDelay=0):
        self.name = name
        self.toFlowID = toFlowID
        self.address = address
        self.device_id = device_id
        self.swNum = device_id + 1
        self.p4info = None
        self.bmv2_json_file_path = NotImplemented   # set this at programming time
        self.p4info_file_path = p4info_file_path
        self.p4info_helper = p4runtime_lib_helper.P4InfoHelper(p4info_file_path)
        self.channel = grpc.insecure_channel(self.address)
        if proto_dump_file is not None:
            interceptor = GrpcRequestLogger(proto_dump_file)
            self.channel = grpc.intercept_channel(self.channel, interceptor)
        self.client_stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
        self.proto_dump_file = proto_dump_file
        self.p4configjson = p4configjson
        ## below is from me:
        self.stop = False
        self.defaultRules = []
        self.activePorts = {}
        self.activePorts[1] = 0
        self.inactivePorts = [] 
        self.activeServices = {}
        self.master = False
        self.stream_out_q = Queue()
        self.qlogfile = open('logs/'+ str(self.device_id) + '.log', "w+")
        self.qlogfileFirst = False
        self.numdigest = 0
        self.vnfList = []
        self.services = []
        self.flowRates = {}
        self.queueDepth = queueDepth
        self.thriftPort = thriftPort
        self.queueRate = queueRate
        self.overloadDetected = False
        self.migThreads = []
        self.controlPlaneDelay = controlPlaneDelay
        self.overloading = 0
        
        def stream_req_iterator():
            while True:
                p = self.stream_out_q.get()
                if p is None:
                    break          
                yield p

        def stream_recv(self):
            i = 0
            #pr = cProfile.Profile()
            for msg in self.stream:
                tStart = time()
                if msg.HasField('packet'):
                    if msg.packet.payload.encode('hex')[0:4] == '3341' or msg.packet.payload.encode('hex')[0:4] == '3143':
                        #print msg.packet.payload.encode('hex') + ' recevied from ' + str(self.name)
                        if (msg.packet.payload.encode('hex')[20] == str(self.swNum) and (msg.packet.payload.encode('hex')[0:4] == '3341')):
                            # this packet is a sync thing received from a migration source:
                            #print msg.packet.payload.encode('hex')
                            migThread = threading.Thread(target=self.doCPSYnc, args=(msg,))
                            migThread.start()
                        else:
                            migThread = threading.Thread(target=self.processMigPkt, args = (msg,))
                            migThread.start()
                        #print "processing migpacket took %f seconds"% float(time() - tStart)
                    else:
                        pkt = controlPacket.controlPacket(msg,self.name, ts=float(tStart))
                        # # break if no valid ethtype can be derived
                        if hasattr(pkt.eth,'type') and pkt.eth != None:
                            discList = [0xffff, 0xffee, 0xeffe]
                            ignoreList = [0x86dd, 0x0806]
                            if pkt.eth.type in discList:
                                thread = threading.Thread(target=self.processDiscPacket, args=(pkt,))
                                thread.start()
                                continue
                            elif hex(pkt.eth.type) not in ignoreList and pkt.ip != None:
                                thread = threading.Thread(target=self.processpacketIn, args=(pkt,))
                                thread.start()
                elif msg.HasField('arbitration'):
                    print('arbitration packet recieved!')
                    if not msg.arbitration.status.message == "Is master":
                        print('Error setting controller as master for device')
                    else:
                        self.master = True
                elif msg.HasField('digest'):
                    # Digest message received. Send digestACK back:
                    self.digestMessageACK(msg.digest.digest_id,msg.digest.list_id)
                    self.numdigest += 1
                    digFields = self.p4info_helper.get_digest_fields_by_id(msg.digest.digest_id)
                    # convert message to json format:
                    dictMsg = google.protobuf.json_format.MessageToDict(msg)
                    # read information to a dictionary:
                    infoDict = {}
                    printVals = []
                    printHdrs = []
                    enq_qdepth = None 
                    deq_qdepth = None 
                    deq_timedelta = None
                    threshold = None 
                    timestamp = None
                    flowID = None 
                    numPackets = None
                    enq_timestamp = None
                    for x in range(0,len(digFields)):
                        for y in digFields[x]:
                            infoDict[y] = {}
                            infoDict[y]['value'] = int(bytes(base64.decodestring(dictMsg['digest']['data'][0]['struct']['members'][x]['bitstring'])).encode('hex'),16)
                            infoDict[y]['bitlength'] = digFields[x][y]
                            if self.qlogfileFirst == False:
                                printHdrs.append(str(y))
                            printVals.append(infoDict[y]['value'])
                            if False == True:
                                print '%s, (%i bit): %i' % (y,infoDict[y]['bitlength'],infoDict[y]['value'])
                            # save values
                            if str(y) == str('enq_qdepth'):
                                enq_qdepth = infoDict[y]['value']
                            if str(y) == str('deq_qdepth'):
                                deq_qdepth = infoDict[y]['value']
                            if str(y) == str('deq_timedelta'):
                                deq_timedelta = float(infoDict[y]['value'])/float(1000000) # convert to ms
                            if str(y) == str('threshold'):
                                threshold = infoDict[y]['value']
                            if str(y) == str('timestamp'):
                                timestamp = infoDict[y]['value']
                            if str(y) == str('flowID'):
                                flowID = infoDict[y]['value']
                            if str(y) == str('numPackets'):
                                numPackets = infoDict[y]['value']
                            if str(y) == str('enq_timestamp'):
                                enq_timestamp = infoDict[y]['value']                            

                    if enq_qdepth != None and deq_qdepth != None and deq_timedelta != None and enq_timestamp != None:
                        # print 'SWITCH OVERLOADING!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
                        # print "enq_qdepth %s" % enq_qdepth
                        # print "deq_qdepth %s" % deq_qdepth
                        # print "deq_timedelta %s" % deq_timedelta
                        
                        # figure out what to do
                        # create a thread that runs the checks for migration and initializes the migration.
                        # runMigration = False
                        # if self.overloadDetected == False:
                        #     runMigration = True
                        # # try:
                        # #     if (time() - float(self.overloadDetected)) > float(10):
                        # #         runMigration = True
                        # # except:
                        # #     pass
                        
                        t = threading.Thread(target=pktMon.addpktDigestReading, args=(self.name , enq_qdepth , deq_qdepth, deq_timedelta, enq_timestamp))
                        t.start()
                        #print 'enqdepth: %i, deqdepth:%i' % (enq_qdepth, deq_qdepth)
                        
                        
                        if (enq_qdepth < deq_qdepth) and (deq_qdepth > 20):
                            #print "enqQdepth: %f deqQdepth: %f" %(float(enq_qdepth), float(deq_qdepth))
                            # NO SCALING IF CONTINUE BELOW HERE!
                            #continue
                            if self.overloadDetected == False: # and self.overloading > 5:
                                self.overloadDetected = tStart
                                migrateThread = threading.Thread(target=flowHandler.migrationHandler, args=(self, enq_timestamp))
                                migrateThread.start()
                                print('Switch %s overloading!!!!' % self.name)

                        # Start the procedure to redirect the load to an other switch (if possible). 
                        # if no solution exists, a new hardware switch should be added. 

                        # This can be a problem....
                    elif threshold != None and timestamp != None and flowID != None and numPackets != None:
                        # this is a packet for rates....
                        t = threading.Thread(target=flowMonitor.addReading, args=(flowID, timestamp, numPackets, self))
                        t.start()
                        #flowMonitor.addReading(flowID, timestamp, numPackets, self)
                        #print "%i/%i at timestamp %i for flowID %s from switch %s" % (numPackets, threshold, timestamp, flowID, self.name)
                    else:
                        print ' begin hellup'
                        if enq_qdepth == None:
                            print 'enq_qdepth is none'
                        if deq_qdepth == None:
                            print 'deq_qdepth is none'
                        if deq_timedelta == None:
                            print 'deq_timedelta is none'
                        print ' eind hellup'
                    # # writ things to file
                    # if self.qlogfileFirst == False:
                    #     self.qlogfile.write(str(printHdrs) + '\n')
                    #     self.qlogfileFirst = True

                    # self.qlogfile.write(str(printVals) + '\n')
                else:
                    print('unknown packet received')
                # has completed successfully
                tElapsed = time() - tStart
                #print("Elapsed time for packetin/out: %.20f ms" %(tElapsed * 1000))

        self.stream = self.client_stub.StreamChannel(stream_req_iterator())
        self.stream_recv_thread = threading.Thread(target=stream_recv, args=(self,))
        self.stream_recv_thread.start()
                
        # send masterarbitrationupdate:
        req = p4runtime_pb2.StreamMessageRequest()
        arbitration = req.arbitration
        arbitration.device_id = self.device_id
        arbitration.election_id.high = 0
        arbitration.election_id.low = 1
        self.stream_out_q.put(req)
        switchFinder.addSwitch(self)
        #connections.append(self)
    def doCPSYnc(self, msg):
        """
        This function strips timing information and forwards the packet to the migration destination.
        """
        
        sleep(self.controlPlaneDelay)
        #print "packet forwarded!"
        migDstSwNum = msg.packet.payload.encode('hex')[21]
        sw = switchFinder.findSwitchBynumber(int(migDstSwNum))
        sw.sendPacketOutRaw(pkt=msg.packet.payload)
        
    def processpacketIn(self, pkt):
        # print "Packetin received from switch %s" % self.name
        # print "packet: %s" % (str(pkt.payload.encode('hex'))) 
        h, flowID = getHash(srcIP=pkt.srcIP, dstIP=pkt.dstIP, srcPort=pkt.srcPort,dstPort=pkt.dstPort, ipProto=pkt.ip.p, srcHost=self.name)

        if h[-1] == True or str(h[-1]) == str(self.name):
            # packet does not yet exist, do everything
            doServices = False

            if pkt.flowID == None:
                pkt.flowID = int(random.getrandbits(30))
                # if applicable, add hosts to the graph
                pkt.addLinktoGraph()
            
                
                
            # check whether this flow should go through a VNF.
            VNF = flowHandler.getService(srcMAC=pkt.srcMAC, dstMAC=pkt.dstMAC, srcIP=pkt.srcIP, srcPort=pkt.srcPort, dstIP=pkt.dstIP, dstPort=pkt.dstPort, protocol=pkt.ip.p)
            VNFList = dbConnect.getFlowVNFS(srcIP=pkt.srcIP, dstIP=pkt.dstIP, srcPort=pkt.srcPort, dstPort=pkt.dstPort, ipProtocol = pkt.ip.p)
            processedVNFList = dbConnect.searchVNFSbyFlow(flowID=pkt.flowID)

            VNF = None
            # search the first NF that has to be processed now:
            for vnf in VNFList:
                if vnf['vnfName'] not in processedVNFList:
                    VNF = vnf['vnfName']
                    break

            # check which actions already are assigned to flow (and which are already processed):
            # change destination and install service to switch
            if VNF== 'proxyStateless':
                print 'we have a proxystateless machine!!!'
                # We have a packet that has to be processed by the proxy before it goes to its destination.
                dstSw = flowHandler.assignService(VNF)
                # install service on dstSw
                # TODO
                switchFinder.findSwitch(dstSw).installVNF(pkt=pkt, VNF=VNF)
                # calculate a new path for the packet to the assigned switch: do not remove flowID at the last switch
                pkt.realDstHost = dstSw
            elif VNF == 'packetCounter':
                # do packetcounter
                #print 'do packetcounter'
                dstSw = flowHandler.assignService(VNF)
                switchFinder.findSwitch(dstSw).installVNF(pkt=pkt, VNF=VNF)
                pkt.realDstHost = dstSw
            elif VNF == None:
                pkt.realDstHost = pkt.dstMAC
            

            # calculate the path from the current location of the packet (the receiving switch) to the destination
            path = findRoute(pkt.recv_sw,pkt.realDstHost)
            if path == []:
                print "iets foutgegaan in berekenen route"
                removeHash(srcIP=pkt.srcIP, dstIP=pkt.dstIP, srcPort=pkt.srcPort,dstPort=pkt.dstPort, ipProto=pkt.ip.p, srcHost=self.name)
                return
            
            # path has been found.
            firstSwitch = pathFindFirstSwitch(path) 
            lastSwitch = pathFindLastSwitch(path)
            #print 'lastswitch is: %s' % str(lastSwitch)
            if lastSwitch != None and str(lastSwitch) != 'None':
                updateHash(srcIP=pkt.srcIP, dstIP=pkt.dstIP, srcPort=pkt.srcPort,dstPort=pkt.dstPort, ipProto=pkt.ip.p, srcHost=self.name, dstHost=lastSwitch, flowID=int(pkt.flowID))
            # get flow infromation. If no result is shown, generate a new flowID and add it to the database
            # flow is distinguished based on following fields
            # srcHost
            # srcPort
            # ipv4 protocol
            # dstHost
            # dstPort
            
            if pkt.flowID is not None:
                flowInfo = dbConnect.searchFlowTable(flowID=pkt.flowID, srcIP=pkt.srcIP, srcPort=pkt.srcPort, ipProtocol=pkt.ip.p, dstIP=pkt.dstIP, dstPort=pkt.dstPort, vnf=VNF)

            if len(flowInfo) == 0:
                # add new entry. this one is not correct:
                print "Packet with new flowID %s" % (pkt.flowID)
                # add the new flow to the table:
                sequence = dbConnect.addFlowTableEntry(flowID=str(pkt.flowID), srcHost=str(path[0]), dstHost=str(path[-1]), vnf=str(VNF), srcIP=pkt.srcIP, srcPort=pkt.srcPort, ipProtocol=pkt.ip.p, dstIP=pkt.dstIP, dstPort=pkt.dstPort)
            else:
                sequence = flowInfo[0]['sequence']
            # install path
            #print path
            installStatus = flowHandler.installLabelPath(path=path,pkt=pkt,firstSwitch=str(firstSwitch),lastSwitch=str(lastSwitch), sequence=sequence)
            
            if installStatus == False:
                print "installing path failed somewhere."
                removeHash(srcIP=pkt.srcIP, dstIP=pkt.dstIP, srcPort=pkt.srcPort,dstPort=pkt.dstPort, ipProto=pkt.ip.p, srcHost=self.name)
                return 
            if lastSwitch != None:
                lastSw = switchFinder.findSwitch(lastSwitch)
            flowID = int(pkt.flowID)
        elif h != False:
            # packet already exists. send the packet to the destination. 
            lastSw = switchFinder.findSwitch(h[-1])
            flowID = flowID
        else:
            h = [False] #beunbeunbeun
            while (h[-1] == False or str(h[-1]) == str(self.name)):
                # buffer this packet until h != false anymore
                print 'Packet buffered!%s' % (str(h))
                h, flowID = getHash(srcIP=pkt.srcIP, dstIP=pkt.dstIP, srcPort=pkt.srcPort,dstPort=pkt.dstPort, ipProto=pkt.ip.p, srcHost=self.name)
                if type(h) == type(None):
                    h = [False]
            lastSw = switchFinder.findSwitch(h)
            flowID = flowID

            # print("poblempaket!")
            # print('h: %s' % str(h))
            # print('flowID: %s' % str(flowID))
            # print pkt.payload.encode('hex')
            # lastSw = None
        # send packetOut    
        if lastSw != None and flowID != False:
            lastSw.sendPacketOutLabel(pkt.payload[:14] + pkt.payload[16:], int(flowID))

    def installRulesOnSwitch(self, installRules):
        for installRule in installRules:
            modify = False
            action_params = dbConnect.getInstallRule(sID=str(self.name), table_name=str(installRule["table_name"]), action_name=str(installRule["action_name"]), default_action=str(installRule["default_action"]), match_fields=str(installRule["match_fields"]))
            if len(action_params) > 0: 
                modify = True
                # if rule exists and action_params is the same, don't install and continue with the next in the loop
                if str(action_params) == str(installRule["action_params"]):
                    #print "rule already exists: %s" % str(installRule)
                    continue
            dbConnect.addInstalledRule(sID=self.name, table_name=installRule["table_name"], action_name=installRule["action_name"], default_action=installRule["default_action"], match_fields=installRule["match_fields"], action_params=installRule["action_params"])
            try:
                self.WriteTableEntry(
                    self.p4info_helper.buildTableEntry(
                        table_name = installRule["table_name"],
                        default_action = installRule["default_action"],
                        match_fields = installRule["match_fields"],
                        action_name = installRule["action_name"],
                        action_params = installRule["action_params"]                        
                    ),
                    modify = modify             
                )
            except Exception as e: 
                print("Something happened when installing a rule on switch %s" % str(self.name))
                print "Rule %s" % str(installRule)
                print(e)
                continue

    def sendPacketOutLabel(self, payload,flowID):
        sleep(self.controlPlaneDelay)
        #print "sending packetout to switch %s" % self.name
        flowIDbyte = ('%%0%dx' % (4 << 1) % flowID).decode('hex')[-4:]
        #flowIDbyte += bytearray(flowID)
        packet_out_req = p4runtime_pb2.PacketOut()
        packet_out_req.payload = bytes('\24\063') + bytes(flowIDbyte) + bytes(payload)
        req = p4runtime_pb2.StreamMessageRequest()
        req.packet.CopyFrom(packet_out_req)
        self.stream_out_q.put(req)

    def processMigPkt(self, msg):
        sleep(self.controlPlaneDelay)   
        ts = time()
        #print "Pkt received from %s %s" % (self.name, msg.packet.payload.encode('hex'))
        try:
            idHdr = str(msg.packet.payload.encode('hex')[0:4])
            migFlowID = int(msg.packet.payload.encode('hex')[4:12], 16)
            subProtocol = str(msg.packet.payload.encode('hex')[12:14])
            sequenceID = int(msg.packet.payload.encode('hex')[14:18], 16)
            intVNFID = int(msg.packet.payload.encode('hex')[18:20],16)
            sessionID = int(msg.packet.payload.encode('hex')[20:22], 16)
            flowID = int(msg.packet.payload.encode('hex')[22:30], 16)
        except:
            print 'error in packetpayload:'
            print msg.packet.payload.encode('hex')
        if subProtocol == 'aa' or subProtocol == '55':
            print "pkt is: %s" % msg.packet.payload.encode('hex')
            ts_u = int(msg.packet.payload.encode('hex')[-12], 16)
            pktMon.addMigPktReading(s_name=self.name, sequenceID=sequenceID, VNFID=intVNFID, sessionID=sessionID, flowID=flowID, ts_u=ts_u)
            # add logging rule to logDB
            #dbConnect.addFlowLog(flowID=flowID, ts=ts_u, recvSw=self.name, sequenceID=sequenceID, VNFID=intVNFID, subProtocol=subProtocol)
        
            print "Timingrommel ontvangen (%s), ts: %s!" % (subProtocol, str(ts_u))
            # get the flowStatus. If the '3c' packet has been missed, 
        
        elif subProtocol == '3c': # acceptflow packet from migration destination
            print """
            Initial sync completed.
            Sync process is in update phase, where the migration destination is updated.

            Now change to 'forward' state. 
            This will cause the secondary switch to process the packets.
            State updates will not be accepted anymore for this flow.
            """
            
            # This is an initial sync packet
            # Now signal the migration destination switch that we can switch to the forward phase.
            # put the corresponding transmission algorithm into the next phase
            result = dbConnect.getMigSrcSw(flowID=flowID, VNFID=intVNFID)
            if result == None:
                print 'error getting dstSw, nothing returned from query %s' % str(result)
                return
            if 'dstHost' not in result:
                print 'Error getting dstSw!'
                print result
                return
            srcSw = switchFinder.findSwitch(result['dstHost'])
            pktMon.addNewMigrationLine(srcSw=srcSw.name, dstSw=self.name, ts=ts, phase=15, flowID=flowID)
            # spawn a new thread that
            # 1. waits for the rule installation to be complete
            # 2. kicks the process to the flowhandler state
            # immediately go to new state. 
            t = threading.Thread(target=flowHandler.flowMigratetoForwardPhase, args=(srcSw, self, flowID, intVNFID))
            t.start()
        elif subProtocol == 'ff' or subProtocol == '3f':
            # this is an ack for the forwardflow state.

            print """
            Update phase completed (ack received from srcSrcSw).
            Now install the remaining path to divert traffic from migsrc to migdst immediately,
            and therefore releaving migsrc.
            Keep hanging 1 second after the process to prevent excessive migrations
            """
            dstSwName = dbConnect.searchFlowMigrateDstHost(flowID=flowID, srcSw=self.name)
            if dstSwName == None:
                return 
            srcSw = switchFinder.findSwitch(dstSwName)
            pktMon.addNewMigrationLine(srcSw=srcSw.name, dstSw=dstSwName, ts=ts, phase=30, flowID=flowID)
            t = threading.Thread(target=flowHandler.flowMigrateFinish, args=(self, dstSwName, flowID, intVNFID))
            t.start()
            # remove old paths
            # change db information
            #    
            # migration has completed.
            # if control plane sync is 1, forward the packet to the destination if it is not an acknowledgement.          

    def processDiscPacket(self, pkt):
    # broadcast protocol packet
    # some way to handle removal of links
        port = int(pkt.handleDiscPacket())
        if port < 0:
            print "error with handleDiscPacket"
            return
        # if port was inactive, make it active again, since packet has been received
        if port in self.inactivePorts:
            self.inactivePorts.remove(port)
        # if port was active, reset error count to 0
        self.activePorts[port] = 0

    def sendPacketOutMigration(self, flowID, migProcessFlowID, migSubProtocol, migSequenceID, migVNFID, migSessionID, networkInfo):
        # allocate buffers:
        # buff_migSubProtocol = array('b', b' '*8)
        # buff_migSequenceID = array('b',b' '* 16)
        # buff_migVNFID = array('b',b' '* 8)
        # buff_migSrcSw = array('b',b' '*8)
        # buff_migDstsw = array('b',b' '*8)
        # buff_migStatus = array('b',b' '*8)
        # buff_migSessionID = array('b',b' '*8)
        sleep(self.controlPlaneDelay)

        buff_indicator = bitstring.BitArray(uint=int(0x3341), length=16)
        buff_migSubProtocol = bitstring.BitArray(uint=int(migSubProtocol),length=8)
        buff_migSequenceID = bitstring.BitArray(uint=int(migSequenceID),length=16)
        buff_migVNFID = bitstring.BitArray(uint=int(migVNFID),length=8)
        buff_migSessionID = bitstring.BitArray(uint=int(migSessionID),length=8)
        buff_migProcessFlowID = bitstring.BitArray(uint=int(migProcessFlowID), length=32)
        buff_flowID = bitstring.BitArray(uint=int(flowID), length=32) # the flowid that is migrated
        header = buff_migSubProtocol + buff_migSequenceID + buff_migVNFID + buff_migSessionID

        if 'srcIP' in networkInfo and 'dstIP' in networkInfo and 'srcPort' in networkInfo and 'dstPort' in networkInfo and 'ipProtocol' in networkInfo:
            buff_migSrcIP = bitstring.BitArray(uint=int(struct.unpack("!I", socket.inet_aton(networkInfo['srcIP']))[0]),length=32)
            buff_migDstIP = bitstring.BitArray(uint=int(struct.unpack("!I", socket.inet_aton(networkInfo['dstIP']))[0]),length=32)
            buff_migSrcPort = bitstring.BitArray(uint=int(networkInfo['srcPort']),length=16)
            buff_migDstPort = bitstring.BitArray(uint=int(networkInfo['dstPort']),length=16)
            buff_migIPProtocol = bitstring.BitArray(uint=int(networkInfo['ipProtocol']),length=8)

            netInfoHeader = buff_flowID + buff_migSrcIP + buff_migDstIP + buff_migSrcPort + buff_migDstPort + buff_migIPProtocol
            header = header + netInfoHeader 
        # else:
        #     buff_ind = bitstring.BitArray(uint=int(0x1433), length=16)
        #     netInfoHeader = buff_ind + buff_flowID
        #     header = header + netInfoHeader 

        #print "sending packetout to switch %s" % self.name        
        packet_out_req = p4runtime_pb2.PacketOut()
        
        packet_out_req.payload = buff_indicator.tobytes() + buff_migProcessFlowID.tobytes() + header.tobytes()
        req = p4runtime_pb2.StreamMessageRequest()
        req.packet.CopyFrom(packet_out_req)
        #print "sending packet %s to switch %s" % (req.packet.payload.encode('hex'), self.name)
        self.stream_out_q.put(req)

    def sendPacketOutRaw(self, pkt):
        
        sleep(self.controlPlaneDelay)
        #print "sending packetout to switch %s" % self.name        
        packet_out_req = p4runtime_pb2.PacketOut()
        
        packet_out_req.payload = pkt
        req = p4runtime_pb2.StreamMessageRequest()
        req.packet.CopyFrom(packet_out_req)
        #print "sending packet %s to switch %s" % (req.packet.payload.encode('hex'), self.name)
        self.stream_out_q.put(req)

    def removeRule(self,rule):
        if self.checkExistRule(rule) == True:
            self.DeleteTableEntry(
                self.p4info_helper.buildTableEntry(
                    table_name = rule["table_name"],
                    match_fields = rule["match_fields"],
                    action_name = rule["action_name"],
                    action_params = rule["action_params"]
                )
            )

    def installVNF(self, pkt, VNF):
        # Service has to be performed.
        installRules = []
        if VNF == 'proxyStateless':
            # get info from database
            dbInfo = dbConnect.searchProxyStateless(srcIP=pkt.srcIP, dstIP=pkt.dstIP)

            if dbInfo == []:
                # no info from database.
                # not installing anything
                return
            else:
                dbInfo = dbInfo[0]

            installRule = {}
            installRule["default_action"] = False
            installRule["table_name"] = "apply_proxy_stateless_tbl"
            installRule["match_fields"] = {
                                            "flowID.flowID": int(pkt.flowID),
                                            "ipv4.dstAddr": str(dbInfo['dstIP']),
                                            "ipv4.srcAddr": str(dbInfo['srcIP']),
                                            }
            installRule["action_name"] = "apply_proxy_stateless"
            installRule["action_params"] = {
                                            "mac_Addr": str(dbInfo['newDstMAC']),
                                            "new_dst": str(dbInfo['newDstIP'])
                                        }
            installRules.append(installRule)
        elif VNF == 'packetCounter':
            print 'installing packetCounter rules! on switch %s' % self.name
            installRule = {}
            installRule['default_action'] = False
            installRule['table_name'] = 'apply_packetCounter_stateful_flowID_tbl'
            installRule['match_fields'] = {
                                            "flowID.flowID": int(pkt.flowID),
                                        }
            installRule["action_name"] = "apply_packetCounter_stateful_flowID"
            installRule["action_params"] = {
                                        }
            installRules.append(installRule)

        self.installRulesOnSwitch(installRules)

    def checkExistRule(self,rule):
        # check if a rule is installed on the system that has the same properties
        # could be easier (if installRule not in Installrules), but I have added a timestamp of installation
        if rule["table_name"] in self.installedRules.keys():
            print self.installedRules
            for installedRule in self.installedRules[rule["table_name"]]:
                if installedRule["table_name"] == rule["table_name"]:
                    if installedRule["match_fields"] == rule["match_fields"]:
                        if installedRule["action_name"] == rule["action_name"]:
                            if installedRule["action_params"] == rule["action_params"]:
                                return True
        return False

    def StreamDigestMessages(self, digest_id, dry_run=False):
        #send a digest entry INSERT message to init the streaming process
        activation_request = p4runtime_pb2.WriteRequest()
        activation_request.device_id = self.device_id
        activation_request.election_id.low = 1
        activation_request.election_id.high = 0
        update = activation_request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.digest_entry.digest_id = digest_id
        update.entity.digest_entry.config.max_timeout_ns = 1
        update.entity.digest_entry.config.max_list_size = 1
        update.entity.digest_entry.config.ack_timeout_ns = 10000

        if dry_run:
            print "P4Runtime Enable digest %s on switch %s" % (digest_id, self.device_id)
        else:
            self.client_stub.Write(activation_request)

    def digestMessageACK(self,digest_id,list_id):
        req = p4runtime_pb2.StreamMessageRequest()
        digest_ack = req.digest_ack
        digest_ack.digest_id = digest_id
        digest_ack.list_id = list_id
        self.stream_out_q.put(req)

    @abstractmethod
    def buildDeviceConfig(self, **kwargs):
        return p4config_pb2.P4DeviceConfig()

    def shutdown(self):
        #self.requests_stream.close()
        self.stream_out_q.put(None)
        self.stop = True
        self.qlogfile.flush()
        self.qlogfile.close()
        
        if not hasattr(self,'status'):
            print "Switch %i has received %i digests" %(self.device_id, self.numdigest)
    
        self.stream_recv_thread.join()
        
        #self.stream_msg_resp.cancel()

    def SetForwardingPipelineConfig(self, p4info, dry_run=False, **kwargs):

        device_config = self.buildDeviceConfig(**kwargs)

        device_config.reassign = True
        with open(kwargs['bmv2_json_file_path']) as f:
            device_config.device_data = f.read()
        
        self.bmv2_json_file_path = kwargs['bmv2_json_file_path']
        #return
        #with open(bmv2_json_file_path) as f:
        #    device_config.device_data = f.read()
    
        request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        request.election_id.low = 1
        request.device_id = self.device_id
        config = request.config
        config.p4info.CopyFrom(p4info)
        config.p4_device_config = device_config.SerializeToString()

        request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
        if dry_run:
            print "P4Runtime SetForwardingPipelineConfig:", request
        else:
            self.client_stub.SetForwardingPipelineConfig(request)
    
    def GetForwardingPipelineConfig(self, p4info, dry_run=False, **kwargs):
        request = p4runtime_pb2.GetForwardingPipelineConfigRequest()
        request.device_id = self.device_id
        request.response_type = p4runtime_pb2.GetForwardingPipelineConfigRequest.DEVICE_CONFIG_AND_COOKIE
        rep = self.client_stub.GetForwardingPipelineConfig(request)
        if rep is not None and self.p4info is not None:
            rep.config.p4info.CopyFrom(self.p4info)

    def DeleteTableEntry(self, table_entry, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        # can't remove default entries:
        if not table_entry.is_default_action:
            update.type = p4runtime_pb2.Update.DELETE
            update.entity.table_entry.CopyFrom(table_entry)
            if dry_run:
                print "P4Runtime Write:", request
            else:
                self.client_stub.Write(request)

    def WriteTableEntry(self, table_entry, modify=False, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        if table_entry.is_default_action or modify == True:
            update.type = p4runtime_pb2.Update.MODIFY
        else:
            update.type = p4runtime_pb2.Update.INSERT
        update.entity.table_entry.CopyFrom(table_entry)
        if dry_run:
            print "P4Runtime Write:", request
        else:
            self.client_stub.Write(request)
    #def parseResponse(response):
    #    if response.entities:

    def printTables(self,only_default=True):
        tableDict = {}
        for tbl in self.p4info_helper.p4info.tables:
            tableName = self.p4info_helper.get_tables_name(tbl.preamble.id)
            tableDict[tableName] = {}
            tableDict[tableName]['match_fields']=[]
            tableDict[tableName]['actions']={}

            # Default action:
            for rule in self.defaultRules:
                if rule['table_name'] == tableName:
                    if rule['default_action'] == True:
                        tableDict[tableName]['default_action'] = rule['action_name']


            for tableEntry in self.ReadTableEntries(table_id = tbl.preamble.id):
                for entity in tableEntry.entities:
                    entry = entity.table_entry
                    tableName = self.p4info_helper.get_tables_name(entry.table_id)

                    action = entry.action.action
                    action_name = self.p4info_helper.get_actions_name(action.action_id)
                    tableDict[tableName]['actions'][action_name] = {}
                    tableDict[tableName]['actions'][action_name]['match_fields'] = {}
                    tableDict[tableName]['actions'][action_name]['action_params'] = {}

                    # loop through all installed table rules for action params:
                    for action_param in action.params:
                        param_name = self.p4info_helper.get_action_param_name(action_name, action_param.param_id)
                        if str(param_name) == 'mac_Addr':
                            param_value = print_mac_addr(action_param.value)
                        elif str(param_name) == 'new_dst':
                            try:
                                param_value = str(socket.inet_ntop(socket.AF_INET, action_param.value[0]),action_param.value[1])
                            except:
                                param_value = str(socket.inet_ntop(socket.AF_INET, action_param.value))
                        elif str(param_name) == 'port':
                            param_value = str(int(''.join(str(x) for x in [str(ord(x)) for x in action_param.value])))
                        else:
                            param_value = action_param.value
                        tableDict[tableName]['actions'][action_name]['action_params'][param_name] = param_value
                        
                    # loop through all installed table rules for matching fields and their values:
                    for match in entry.match:
                        match_field_name = str(self.p4info_helper.get_match_field_name(tableName, match.field_id))
                        match_field = self.p4info_helper.get_match_field_value(match)
                        if str(match_field_name) == 'ipv4.dstAddr' or str(match_field_name) == 'ipv4.srcAddr':
                            
                            try:
                                match_field = str(socket.inet_ntop(socket.AF_INET, match_field[0]),match_field[1])
                            except:
                                match_field = str(socket.inet_ntop(socket.AF_INET, match_field))

                        tableDict[tableName]['actions'][action_name]['match_fields'][match_field_name] = str(match_field)
        for x in tableDict:
            if 'default_action' not in tableDict[x].keys():
                print "Default action missing in table %s" % (x)
        if False:
            if(only_default == True):
                print '\n----- Reading tables rules for %s -----' % self.name
                print "Default rules:"
            else:
                print(json.dumps(tableDict,sort_keys=True,indent=4,separators=(',', ': ')))

    def ReadTableEntries(self, table_id=None, dry_run=False):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        table_entry = entity.table_entry
        if table_id is not None:
            table_entry.table_id = table_id
        else:
            table_entry.table_id = 1
        if dry_run:
            print "P4Runtime Read:", request
        else:
            for response in self.client_stub.Read(request):
                yield response
    def checkSwLoad(self):
        # this is a placeholder for the load checking algorithm
        return True

    def WriteMulticastGroupEntry(self, mc_entry, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.packet_replication_engine_entry.CopyFrom(mc_entry)
        if dry_run:
            print "P4Runtime Write:", request
        else:
            self.client_stub.Write(request)

class GrpcRequestLogger(grpc.UnaryUnaryClientInterceptor,
                        grpc.UnaryStreamClientInterceptor):
    """Implementation of a gRPC interceptor that logs request to a file"""

    def __init__(self, log_file):
        self.log_file = log_file
        with open(self.log_file, 'w') as f:
            # Clear content if it exists.
            f.write("")

    def log_message(self, method_name, body):
        with open(self.log_file, 'a') as f:
            ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            msg = str(body)
            f.write("\n[%s] %s\n---\n" % (ts, method_name))
            if len(msg) < MSG_LOG_MAX_LEN:
                f.write(str(body))
            else:
                f.write("Message too long (%d bytes)! Skipping log...\n" % len(msg))
            f.write('---\n')

    def intercept_unary_unary(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

class IterableQueue(Queue):
    _sentinel = object()

    def __iter__(self):
        return iter(self.get, self._sentinel)

    def close(self):
        self.put(self._sentinel)