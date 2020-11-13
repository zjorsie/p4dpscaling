from pyblake2 import blake2b
from time import time

flowDict = {}
flowMigDict = {}
flowMigBlockDict = []
# src
#   dst
#     LIST:
#       srcport
#       dstport
#       flowID

def getHash(srcIP, dstIP, srcPort, dstPort, ipProto, srcHost):
    global flowDict
    srcIP = str(srcIP)
    dstIP = str(dstIP)
    srcPort = str(srcPort)
    dstPort = str(dstPort)
    ipProto = str(ipProto)

    netHash = str(hash((srcIP, dstIP, srcPort, dstPort, ipProto, srcHost)))

    if netHash not in flowDict.keys():
        flowDict[netHash] = ([ False ], False)
        return ([ True ], True)
    else:
        return flowDict[netHash][0], flowDict[netHash][1]


def updateHash(srcIP, dstIP, srcPort, dstPort, ipProto, srcHost, dstHost, flowID):
    global flowDict
    srcIP = str(srcIP)
    dstIP = str(dstIP)
    srcPort = str(srcPort)
    dstPort = str(dstPort)
    ipProto = str(ipProto)

    netHash = str(hash((srcIP, dstIP, srcPort, dstPort, ipProto, srcHost))) 
    if dstHost is not None:
        if type(flowDict) != type([]):
            newList = [False, str(dstHost)]
        else:
            newList = flowDict[netHash][0].append(str(dstHost))
        flowDict[netHash] = (newList, int(flowID))


def removeHash(srcIP, dstIP, srcPort, dstPort, ipProto, srcHost):
    global flowDict
    srcIP = str(srcIP)
    dstIP = str(dstIP)
    srcPort = str(srcPort)
    dstPort = str(dstPort)
    ipProto = str(ipProto)
    netHash = str(hash((srcIP, dstIP, srcPort, dstPort, ipProto, srcHost)))
    if netHash in flowDict.keys():
        del flowDict[netHash]

def updateMigHash(srcSwName, dstSwName, flowID, plusStatus, ts=time()):
    global flowMigDict
    migHash = str(hash((str(srcSwName), str(dstSwName), int(flowID))))


    if migHash not in flowMigDict.keys():
        flowMigDict[migHash] = {
            'status': 0,
        }
    flowMigDict[migHash]['status'] += int(plusStatus)
    if flowMigDict[migHash]['status'] == 1:
        flowMigDict[migHash]['tsInit'] = float(ts)
    if flowMigDict[migHash]['status'] == 4:
        flowMigDict[migHash]['installRules'] = float(ts)
    if flowMigDict[migHash]['status'] == 11:
        flowMigDict[migHash]['tsForward'] = float(ts)

def getMigHash(srcSwName, dstSwName, flowID):
    h = str(hash((str(srcSwName), str(dstSwName), int(flowID))))

    if h in flowMigDict.keys():
        return flowMigDict[h]['status']

    return None

def rmMigHash(srcSwName, dstSwName, flowID, ts=time()):
    result = {}
    global flowMigDict
    h = str(hash((str(srcSwName), str(dstSwName), int(flowID))))

    if h in flowMigDict.keys():
        result = flowMigDict[h]
        print result
        try:
            del flowMigDict[h]
        except:
            pass
    result['tsFinish'] = float(ts)
    return result

