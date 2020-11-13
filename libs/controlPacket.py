import dpkt
from dpkt.compat import compat_ord
import socket
import networkx as nx
import netGraph 
import sys
import re
import socket

from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from p4.tmp import p4config_pb2
import monitoringStats as pktMon
import flowHandler
CPU_PORT = 255
HOST_NUM = 1
def inet_to_str(inet):
    """Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def print_mac_addr(address):
    """Convert a MAC address to a readable/printable string
    Args:
        address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
    Returns:
        str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

class controlPacket:
    def __init__(self, pkt, recv_sw, ts):
        self.payload = pkt.packet.payload
        self.metadata = pkt.packet.metadata
        self.in_port = None 
        self.packetStat = None
        self.recv_sw = recv_sw
        self.eth = None
        self.ip = None
        self.icmp = None 
        self.tcp = None 
        self.udp = None
        self.arp = None
        self.flowID = None 
        self.srcIP = None 
        self.dstIP = None 
        self.realDstHost = None

        if str(self.payload.encode('hex')[0:4]) == str('1433'):
            # found something with flowID
            self.flowID = int(str(self.payload.encode('hex')[4:12]),16)
            self.payload = self.payload[6:]
        else:
            self.flowID = None

        tmpethType = str(self.payload[12:14].encode('hex'))

    
        if tmpethType == str('ffff') or tmpethType == str('effe'):
            msg = self.payload[:14] + self.payload[16:]
            self.in_port = int(str(''.join('%02x' % compat_ord(b) for b in self.payload[14:16])[:4]),16)
            self.eth = dpkt.ethernet.Ethernet(str(msg))
        elif tmpethType == str('ffee'):
            msg = self.payload[:14] + self.payload[40:]
            self.in_port = int(str(''.join('%02x' % compat_ord(b) for b in self.payload[14:16])[:4]),16)
            self.eth = dpkt.ethernet.Ethernet(str(msg))

            #self.in_port = int(str(self.payload[14:16]).encode('hex'),16)
            self.packetStat = {}
            self.packetStat['general'] = float(int(str(self.payload[16:20]).encode('hex'),16))
            self.packetStat['packetCounter'] = float(int(str(self.payload[20:24]).encode('hex'),16))
            self.packetStat['proxyStateless'] = float(int(str(self.payload[24:28]).encode('hex'),16))
            self.packetStat['fwStateless'] = float(int(str(self.payload[28:32]).encode('hex'),16))
            self.packetStat['fwStateful'] = float(int(str(self.payload[32:36]).encode('hex'),16))
            self.packetStat['migrate'] = float(int(str(self.payload[36:40]).encode('hex'),16))
            pktMon.addPktSwitchReading(self.recv_sw,self.packetStat, ts=ts)       
        else:
            try:
                self.eth = dpkt.ethernet.Ethernet(self.payload)
            except:
                msg = self.payload[:14] + self.payload[16:]
                self.eth = dpkt.ethernet.Ethernet(str(msg))
                
                
            if not type(self.eth.data) == type(dpkt.ip.IP) and not type(self.eth.data) == type(dpkt.arp.ARP):
                msg = self.payload[:14]+self.payload[16:]
                self.eth = dpkt.ethernet.Ethernet(str(msg))
                self.in_port = int(str(''.join('%02x' % compat_ord(b) for b in self.payload[14:16])[:4]),16)

        if self.eth != None: 
            self.srcMAC = print_mac_addr(self.eth.src)
            self.dstMAC = print_mac_addr(self.eth.dst)
            if type(self.eth.data) == dpkt.ip.IP:
                self.ip = self.eth.data
                self.packetType = 'IP'
                self.srcIP = socket.inet_ntop(socket.AF_INET, self.ip.src)
                self.dstIP = socket.inet_ntop(socket.AF_INET, self.ip.dst)
                if type(self.ip.data) == dpkt.tcp.TCP:
                    self.tcp = self.ip.data
                    self.packetType = 'TCP'
                if type(self.ip.data) == dpkt.udp.UDP:
                    self.udp = self.ip.data
                    self.packetType = 'UDP'
                if type(self.ip.data) == dpkt.icmp.ICMP:
                    self.icmp = self.ip.data
                    self.packetType = 'ICMP'
            elif type(self.eth.data) == dpkt.arp.ARP:
                self.arp = self.eth.data
                self.packetType = 'ARP'
        if self.tcp != None:
            self.dstPort = self.tcp.dport
            self.srcPort = self.tcp.sport
        elif self.udp != None:
            self.dstPort = self.udp.dport
            self.srcPort = self.udp.sport
        else: 
            # icmp or other packet received:
            self.dstPort = 143
            self.srcPort = 143
    

    def handleDiscPacket(self):
        if self.in_port != CPU_PORT and self.in_port is not None:
        # packetins from CPU port are just packets from the controller to the switch, ignore
            if self.eth.type == 0xffff or self.eth.type == 0xffee or self.eth.type == 0xeffe:
                netGraph.addLink(self.recv_sw, str(self.eth.data), self.in_port) # add edge to graph
                return self.in_port
        return '-1'

    def packetPrint(self):
        # remove custom port header
        print('L2: ' + str(self.srcMAC) + ' -> ' + str(self.dstMAC) + ' (eth_type=' + str(self.eth.type)),
        if self.in_port is not None:
            print '), received on port '+ ' ' + str(self.in_port) + ' of switch ' + str(self.recv_sw)
        else:
            print ')'
        if self.ip != None:
            do_not_fragment = bool(self.ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(self.ip.off & dpkt.ip.IP_MF)
            fragment_offset = self.ip.off & dpkt.ip.IP_OFFMASK
            print('L3: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' % (inet_to_str(self.ip.src), inet_to_str(self.ip.dst), self.ip.len, self.ip.ttl, do_not_fragment, more_fragments, fragment_offset))
            if self.tcp != None:
                print('TCP: %s -> %s (seq=%s ack=%s _off=%s flags=%s win=%s sum=%s urp=%s)' %(self.tcp.sport,self.tcp.dport,self.tcp.seq,self.tcp.ack,self.tcp._off,self.tcp.flags,self.tcp.win,self.tcp.sum,self.tcp.urp))
            if self.udp != None:
                print('UDP: %s -> %s (ulen=%s sum=%s)' %(self.udp.sport,self.udp.dport,self.udp.ulen,self.udp.sum))
            if self.icmp != None:
                print('valid ICMP packet received')
        if self.arp != None:
            print('ARP: (OP:'+str(self.arp.op)+', SHA: '+str(print_mac_addr(self.arp.sha))+', SPA: '+str(inet_to_str(self.arp.spa))+', THA: '+str(print_mac_addr(self.arp.tha))+', TPA: '+str(inet_to_str(self.arp.tpa))+')')            
        if self.flowID != None:
            print('FlowID: %s'% self.flowID)
        print ''
    def addLinktoGraph(self):
        # add link to the graph. First check if both hosts are in the network, then add the host if neccessary
        # if source not in network: add the node
        if self.eth is not None: 
            if self.ip is not None:
                if self.recv_sw is not None:
                    if self.srcMAC not in netGraph.getHosts():
                        print "Adding host with MAC address %s to the network" % self.srcMAC
                        netGraph.addHost(self.srcMAC, 'host')
                        netGraph.setHostAttr(self.srcMAC,'hwaddr',self.srcMAC)
                        netGraph.setHostAttr(self.srcMAC,'ipaddr',inet_to_str(self.ip.src))
                        netGraph.setHostAttr(self.srcMAC,'swcon',str(self.recv_sw))
                        if self.in_port is not None:
                            if self.in_port not in netGraph.getNeighborTypePorts(self.recv_sw, 'switch'): 
                                pair = [self.srcMAC,self.recv_sw]
                                pairinv = [self.recv_sw,self.srcMAC]
                                if pair not in netGraph.getLinks():
                                    netGraph.addLink(self.srcMAC,self.recv_sw, self.in_port)
                                    print "Link added between %s and %s" %(self.srcMAC, self.recv_sw)
                                if pairinv not in netGraph.getLinks():
                                    netGraph.addLink(self.recv_sw,self.srcMAC, self.in_port)
                                    print "Link added between %s and %s" %(self.recv_sw, self.srcMAC)
        return True

class controlPacketLight(object):
    def __init__(self, flowID, srcIP, dstIP, srcPort, dstPort, ipProto):
        self.flowID = str(flowID) 
        self.srcIP = str(srcIP)
        self.dstIP = str(dstIP)
        self.dstPort = int(dstPort)
        self.srcPort = int(srcPort)
        self.ipProto = int(ipProto)
