import time

import libs.switchFinder as switchFinder
import libs.appServices as appServices
import libs.dbConnect as dbConnect

def startPacketCounter(dstSwName='s3'):
    # this service needs to:
    # - enable code on the switch
    # - write some behaviour to switch that indicates which things to do
    tStart = time.time()

    sw = switchFinder.findSwitch(dstSwName)
    # add vnf to object
    sw.vnfList.append('packetCounter')
    dbConnect.addVNF(vnfName='packetCounter', prio=-10)
    appServices.addService('packetCounter', None) # this function only does this if it doesn't exist
    res = appServices.addServiceSwitch('packetCounter', sw.name)
    if res != True:
        raise Exception("something went wrong for adding a VNF")
    tPacketSetupService = time.time() - tStart
    print "Service proxy started. The whole process took %f seconds" % (tPacketSetupService)

def startProxyService(dstSwName='s1'):
    # this service needs to:
    # - enable code on a switch
    # - write some rules to the switch to have some behaviour
    # this is the network address translation service that tracks the connections that have to go through the proxy service.
    tStart = time.time()
    sw = switchFinder.findSwitch(dstSwName)
    ruleList = []
    # add any original service rules to the dict. not used now because this is the initializing function, but this may be used in the future
    ruleList.append({
                'origDstIP' : '10.0.1.2',
                'origSrcIP' : '10.0.1.10',
                'newDstIP'  : '10.0.1.20',
                'newMAC'    : '02:00:00:00:02:22'
            }
        )
    ruleList.append({
                'origDstIP' : '10.0.1.2',
                'origSrcIP' : '10.0.1.20',
                'newDstIP'  : '10.0.1.10',
                'newMAC'    : '02:00:00:00:01:11'
            }
        )
    
          
    for rule in ruleList:
        oldDstIP = rule['origDstIP']
        oldSrcIP = rule['origSrcIP']
        newDstIP  = rule['newDstIP']
        newMAC    = rule['newMAC']   
        dbConnect.addProxyStateless(srcIP=oldSrcIP, dstIP=oldDstIP, newDstIP=newDstIP, newDstMAC=newMAC)
        dbConnect.addVNF(vnfName='proxyStateless', srcIP=oldSrcIP, dstIP=oldDstIP)

    # initialize one instance on switch s3:
    appServices.addService('proxyStateless', None)
    appServices.addServiceSwitch('proxyStateless', sw.name)

    # add vnf to object
    sw.vnfList.append('proxyStateless')
    
    tProxySetupService = time.time() - tStart
    print "Service proxy started. The whole process took %f seconds" % (tProxySetupService)

    return

def setupNewInstance(vnf, swName):
    if vnf == 'proxyStateless':
        startProxyService(dstSwName=swName)
    elif vnf == 'packetCounter':
        startPacketCounter(dstSwName=swName)
    else:
        raise Exception("Unknown VNF %s for new instance %s" % (str(vnf), str(swName)))