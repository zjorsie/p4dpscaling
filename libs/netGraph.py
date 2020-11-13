import networkx as nx
import matplotlib
import sys
matplotlib.use('Agg')
import collections
import os
import libs.lockGraphs
import copy

G = nx.DiGraph()
curGraph = nx.DiGraph()

def printGraph(file):
    #return
    global curGraph
    Gtmp = G.copy()
    # only print if changed      
    
    if nx.is_isomorphic(Gtmp,curGraph) == False:
        if libs.lockGraphs.getStatus() == False:

            # remove old file
            try:
                os.remove(file)
            except:
                pass
            matplotlib.pyplot.cla()
            matplotlib.pyplot.clf()
            #labels=dict((n,d['type']) for n,d in Gtmp.nodes(data=True))
            pos = nx.spring_layout(G)
            nx.draw(Gtmp, pos, with_labels = True, node_color='red', font_size=8, font_weight='bold')
            matplotlib.pyplot.savefig(file, format="PNG")
            curGraph = Gtmp
            libs.lockGraphs.clearLock()
        

def addLink(orig_host,recv_host,ingress_port):
    if orig_host not in G.nodes:
        print "orig_host %s not in graph" % orig_host
        return
    if recv_host not in G.nodes:
        print "recv_host %s not in graph" % (recv_host)
        return
    G.add_edge(orig_host, recv_host, port=int(ingress_port))

def delLink(orig_host, recv_host):
    try:
        print "Trying to remove link"
        G.remove_edge(orig_host,recv_host)
        print("link removed!@!!")
    except:
        pass

def addHost(name,h_type):
        G.add_node(name,type=str(h_type))
  
def getHosts():
    return G.nodes()

def setHostAttr(host,key,value):
    Gtmp = G.copy()
    if host in Gtmp.node:
        G.node[host][key] = value
    #print G.node[host]

def getHostAttr(host,key):
    Gtmp = G.copy()
    if host in Gtmp.node:
        return Gtmp.node[host][key]
    return None

def getLinkProperties(src,dst):
    edgeData = G.get_edge_data(src,dst)
    return edgeData

def getLinks():
    return G.edges()

def getHostType(host, h_type):
    Gtmp = G.copy()
    if host in Gtmp.nodes:
        if 'type' in Gtmp.node[host].keys():
            if Gtmp.node[host]['type'] == h_type:
                return True
    return False

def getNeighborTypePorts(host, h_type):
    Gtmp = G.copy()
    ports = []
    for neighbor in Gtmp[host]:
        if getHostType(neighbor, h_type):
            linkInfo = getLinkProperties(host, neighbor)
            if 'port' in linkInfo:
                ports.append(linkInfo['port'])
    return ports

def getNeighborSwitchbyPort(host,port):
    Gtmp = G.copy()
    for neighbor in Gtmp[host]:
        if 'port' in Gtmp[host][neighbor].keys():
            if Gtmp[host][neighbor]['port'] == port:
                print "found neigbor %s on port %i" %(neighbor,port)
                return neighbor
    return None

def getShortestPath(src, dst):
    path = None
    Gtmp = G.copy()
    if src in Gtmp.nodes and dst in Gtmp.nodes:
        if nx.has_path(Gtmp,source=src,target=dst):
            # do nothing if no path can be found between two nodes
            try:
                path = nx.shortest_path(Gtmp,source=src, target=dst)
            except nx.NodeNotFound:
                print("Source %s unknown" % (src))
                return None
            except:
                print 'There is something wrong with finding a shortest route'
                return None
    else:
        print "SRC or DST are not in nodes: path from %s to %s" %(str(src), str(dst))
        print Gtmp.nodes
    return path

def getShortestPathWithoutHost(src, dst, removeHost):
    path = None
    Gtmp = copy.deepcopy(G)
    try:
        Gtmp.remove_node(removeHost)
    except:
        print("something went wrong with removing node from network (getshortestpathwithouthost)")
    if src in Gtmp.nodes and dst in Gtmp.nodes:
        if nx.has_path(Gtmp,source=src,target=dst):
            # do nothing if no path can be found between two nodes
            path = nx.shortest_path(Gtmp,source=src, target=dst)
        else:
            print "No path could be found between %s and %s" % (str(src), str(dst))
            return []
    else:
        print "SRC or DST are not in nodes: path from %s to %s" %(str(src), str(dst))
        print Gtmp.nodes
    return path

def getOutportToDst(src,dst):
    path = getShortestPath(src,dst)
    if path != None:
        if len(path) > 1:
            return int(int(getLinkProperties(src, path[1])['port']))
    return -1



        