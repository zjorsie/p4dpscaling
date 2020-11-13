from time import time
from time import sleep
import dbConnect as dbConnect
import netGraph as netGraph
import random
import libs.appServices as appServices
import libs.flowMonitor as flowMonitor
import libs.netGraph as netGraph
from libs.dbConnect import returnProxyID,getNetworkInFo, addFlowMigrate, searchFlowMigrate,getMigSrcSw,updateFlowMigrate,returnVNFName,searchSubFlow
import libs.switchFinder as switchFinder
import libs.vnfHandler as vnfHandler
from collections import OrderedDict
from operator import getitem
import libs.controlPacket as controlPacket
import libs.netFlows as netFlows
import libs.monitoringStats as pktMon
import threading



pathDict = {}
migrateMargin = 0.1 # percent
EXTRA_PATH_THRESHOLD = 3 # take an extra path length for the path length

def getService(srcMAC, dstMAC, srcIP,srcPort,dstIP,dstPort,protocol):
    # All VNF behaviour is defined here. 
    # They can be implemented by means of:
    #   srcIP
    #   dstIP
    #   srcPort
    #   dstPort
    #   protocol
    # and maybe other things. These things should be in the database
    #TODO: check database for collisions in information combo and service.
    result = dbConnect.searchProxyStateless(srcIP=srcIP, dstIP=dstIP)
    for x in result:
        if 'newDstMAC' in x.keys() and 'newDstIP' in x.keys():
            return "proxyStateless"
    
    return None

def assignService(VNF):
    if appServices.getServiceSwitches(VNF) == []:
        print("VNF %s is not started correctly!" % VNF)
        return
    for x in appServices.getServiceSwitches(VNF):
        # do something to check the load:
        # for now just return the first entry in the list
        return x

def migrationHandler(srcSw, enq_timestamp):
    """This function does:
    For each vnf on overloading switch:
        find pool of switches
        check if enough load could be redistributed to other switches to satisfy the usage statistics (0.75) for each switch in the pool (assumed load numbers don't change)

        if this is possible: migrate largest flows to other switches

        Else: create a new instance and migrate enough flows to the new switch to bring the level to better measures
    """
    
    # check wheter we can redistribute the load to another switch already running the VNF:
    # traffic has to be diverted of the switch, so new path is calculated to not use the switch currently in use

    # start with the control plane delay:
    sleep(srcSw.controlPlaneDelay)
    tmigStart = time()
    pktMon.addNewMigrationLine(srcSw=srcSw.name, dstSw="Unknown", ts=tmigStart, phase=0, flowID=0, tsRel=enq_timestamp)
    srcSw.overloadDetected = tmigStart
    redistributeLoad, dstSw, flowIDList, vnf = checkSwitches(srcSw=srcSw, migrate=False)

    if redistributeLoad != False:
        ts = time()
        for flowID in flowIDList:
            pktMon.addNewMigrationLine(srcSw=srcSw.name, dstSw=dstSw.name, ts=ts, phase=6, flowID=flowID)
        #migrate those flows to the other host
        print("planning to redistribute load to (%s)" % (dstSw.name))
        for flowID in flowIDList:
            print("Migrate flowID %s" %(flowID))
        for flowID in flowIDList:
            initMigThread = threading.Thread(target=initFlowMigrate, args=(srcSw, dstSw, flowID, 0x0f, vnf))
            initMigThread.start()
            #initFlowMigrate(migSrcSw=srcSw, migDstSw=dstSw, flowID=flowID, vnf=vnf)

    else:
        # no solution has been found without migration. Set up a new instance:
        pass
        # spin up a new VNF for the VNF with the largest volume on the overloading switch
        migrateToSwitch, dstSw, flowIDList, vnf = checkSwitches(srcSw=srcSw, migrate=True)
        if migrateToSwitch != False:
            ts = time()
            for flowID in flowIDList:
                pktMon.addNewMigrationLine(srcSw=srcSw.name, dstSw=dstSw.name, ts=ts, phase=7, flowID=flowID)
            print("planning to migrate things to a new VNF switch (%s)" % (dstSw.name))
            for flowID in flowIDList:
                print("Migrate flowID %s" %(flowID))
            # setup a new switch and migrate flows to the new switch:
            vnfHandler.setupNewInstance(vnf=vnf, swName = dstSw.name)
            for flowID in flowIDList:
                initMigThread = threading.Thread(target=initFlowMigrate, args=(srcSw, dstSw, flowID, 0x0f, vnf))
                initMigThread.start()
               #initFlowMigrate(migSrcSw=srcSw, migDstSw=dstSw, flowID=flowID, vnf=vnf)
        else:
            print("No VNF to be set up on other switches. Manually add hardware or change network topology!") 
        ts = time()
        # we have to check if there is a switch that does not have the path
        print "calculations for migration took %f seconds" % float(time() - ts)

def getMigrationOptions(vnf):
    swList = []
    for sw in switchFinder.allSwitches:
        if vnf not in sw.vnfList:
           swList.append(sw.name)
    return swList

def getRebalanceOptions(vnf):
    swList = []
    for sw in switchFinder.allSwitches:
        if vnf in sw.vnfList:
           swList.append(sw.name)
    return swList

def checkSwitches(srcSw, migrate=False):
    # the flow volume that has to be offloaded to stop overloading the switch
    swLoad = float(pktMon.getSwitchLoad(s_name=srcSw.name))
    offLoad = abs(int(swLoad - int(float(srcSw.queueRate) * float(1 - float(migrateMargin))))) # absolute...
    print("We will need to offload %s from the current load of %s"%(int(offLoad), int(swLoad)))
    # check all VNFS that run on the switch: If one solution has been found, redistributing load is feasible and that particular VNF
    for vnf in srcSw.vnfList:
        if migrate == False:
            vnfSwitches = getRebalanceOptions(str(vnf))
        else:
            vnfSwitches = getMigrationOptions(str(vnf))
        #print ("vnfswitches: %s" % (str(vnfSwitches)))
        if str(srcSw.name) in vnfSwitches:
            vnfSwitches.remove(srcSw.name)
        if len(vnfSwitches) < 1:
            # only one VNF running... definately no migration
            continue
        #orders the switches that could handle the load, from low load to high load.
        swDict = checkVNFLoad(vnfSwitches=vnfSwitches, offLoad=offLoad)
        #print swDict
        for swName, swDict in swDict.items():
            if swName == srcSw.name:
                # not much use for this...
                continue
            #print "Checking to offload NF %s from %s to switch %s" %(vnf, srcSw.name, swName)
            dstSw = switchFinder.findSwitch(swName)
            flowIDList = checkRedistributeSwitchLoad(srcSw=srcSw, dstSw=dstSw, offLoad=offLoad, vnf=vnf)
            print "flowIDlist = %s" % str(flowIDList)
            if len(flowIDList) > 0:
                return (flowIDList, dstSw, flowIDList, vnf)
    return False, False, False, False

def checkRedistributeSwitchLoad(srcSw, dstSw, offLoad, vnf):
    """
    This loop checks whether it is possible to offload a flow volume to another switch without overoading that switch. 
    It selects a volume of switches (top 10 largest flows for VNF) and reroutes it ot another switch
    """
    print "checking list %s, vnf %s" % (srcSw.vnfList, vnf)
    if str(srcSw.name) == str(dstSw.name):
        # yeah.. not much use for this since switch is overloading
        return []
    # get largest flows from the source switch
    topFlows = flowMonitor.getSwitchTopLoads(srcSw.name)
    print "topflows: %s" % str(topFlows)
    # for each flowID:
    flowVolume = 0
    flowIDList = []
    for flowID in topFlows:
        newPathLength = checkExtraPathLength(sw=srcSw, newSw=dstSw, flowID=flowID[0], vnf=str(vnf))
        print 'flowID %s has length %i' % (str(flowID) , int(newPathLength))
        if newPathLength <= EXTRA_PATH_THRESHOLD:
            if int(flowID[1]) > 0:
                # this new path without the switch is not too long, so it would be an option
                flowVolume += int(flowID[1])
                flowIDList.append(flowID[0])
        if flowVolume > offLoad:
            # we have reached a solution.
            return flowIDList
    # for some reason we don't have a solution
    return []



def checkVNFLoad(vnfSwitches, offLoad):
    swDict = {}
    for sw in vnfSwitches: # loop through all switches
        if type(sw) == type({}):
            sw = sw['dstHost']

        #print "checkvnfLoad SW %s" % (sw)
        switchObj = switchFinder.findSwitch(sw)
        switchLoad = int(pktMon.getSwitchLoad(s_name=switchObj.name))
        newLoad = int(float(switchLoad) + (float(abs(offLoad)) * float(1 + float(migrateMargin))))
        #print "checkvnfLoad SW %s has load %i and will get load %i with new NF" % (sw, int(switchLoad), newLoad)
        if float(float(1-migrateMargin)*switchObj.queueRate) > float(newLoad): # if switch will not be overloading:
            swDict[sw] = {
                    'curload': int(switchLoad), 
                    'newLoad': int(newLoad), 
                    'maxLoad': int(switchObj.queueRate),
                    'newloadNum': float(float(newLoad)/float(switchObj.queueRate))
                    }

        # order the dict:
    res = OrderedDict(sorted(swDict.items(), key = lambda x: getitem(x[1], 'newloadNum')))
    return res

def checkExtraPathLength(sw, newSw, flowID, vnf):
    # find current flow information in database
    if str(sw.name) == str(newSw.name):
        # shouldn't happen
        return 0

    inHost, outHost = dbConnect.searchSubFlow(host=sw.name, flowID=flowID,vnf=vnf)
    if inHost == "" or outHost == "":
        print 'inhost is: %s, outhost %s' % (inHost, outHost)
        # not sure what happens, but it is not good....h2 pin g
        return 999

    if (str(newSw.name) == str(inHost)) or (str(newSw.name) == str(outHost)):        
        #no option (yet)
        # problem is that inhost or outhost could be performing NFs already, something that isn't supported yet.
        return 999
    
    curInPath = (netGraph.getShortestPath(str(inHost), str(sw.name)))
    curOutPath = netGraph.getShortestPath(str(sw.name), outHost)

    #print "curinpath %s" % str(curInPath)
    #print "curoutpath %s" % str(curOutPath)
    newInPath = netGraph.getShortestPathWithoutHost(str(inHost), newSw.name, sw.name)
    #print "newInPath %s" % str(newInPath)
    newOutPath = netGraph.getShortestPathWithoutHost(newSw.name, outHost, sw.name)
    #print "newOutPath %s" % str(newOutPath)
    return int(len(newInPath) + len(newOutPath) - len(curInPath) - len(curOutPath))

def checkNewSwitchLoad(sw, oldLoad, extraLoad, margin):
    """
    This function checks the new load for a switch.
    """
    if int(int(oldLoad) + int(extraLoad)) < int(int(float(sw.queueRate) * (float(1+float(migrateMargin))))):
        return True
    else:
        return False
        # check if it should work in theory (capacity/max capacity)

        # if it works. do that
    
    #else
        # scale out


    # calculate
        # for each vnf running on the migration src sw
        # if we can balance the load (migrate to other switches)
        # if we have a solution: calculate new path
        # we have a new solution
    
    # else: (load can't be balanced)
    # enable VNF on other switch
    # which switch?

def initFlowMigrate(migSrcSw, migDstSw, flowID, migSubProtocol=0x0f, vnf='None'):
    tStart = time()
    # first send packet to migSrcSwitch
    # it needs to have the following layout:
    # 0x3341 | migration header | 0x1433 | flowID of flow | any relevant information for state transmission
    
    # begin packet 
    # start migration. subprotocol = 0x00 and sequenceID = 0x00
    
    # find the VNFID from the database

    # possible states:
    # 0x00 - no migration/syncing whatsoever
    # 0x0f - initial passive updates from source to dest
    # 0xf0 - active updates (migration destination processes packets)
    
    try: 
        flowID = int(flowID,16)
    except:
        flowID = int(flowID)


    netFlows.updateMigHash(srcSwName=migSrcSw.name, dstSwName=migDstSw.name, flowID=flowID, plusStatus=1, ts=tStart)
    print "Migrate flow %s from %s to %s" % (flowID, migSrcSw.name, migDstSw.name)
    VNFID = dbConnect.returnVNFID(vnf)
    if hex(VNFID) == 0xff:
        print "invalid VNFID"
        print VNFID
        return

    migsessionID = int(migSrcSw.swNum * 16 + migDstSw.swNum)
    headerLength = 0
    

    # check if flowID is already being migrated. exit if it is
    if dbConnect.searchFlowMigrate(flowID=flowID, srcSw=migSrcSw.name) >= 1:
        print "Flow %s is already being migrated" % str(flowID)
        return

    migStatus = 0x0f 
    pkt, networkInfo = createLightPacket(flowID=flowID, swName=migSrcSw.name)
    dbConnect.addFlowMigrate( flowID=flowID, srcSw=migSrcSw.name, dstSw=migDstSw.name, migStatus=migStatus)
    migSrcSw.sendPacketOutMigration(flowID=flowID, migProcessFlowID=migDstSw.toFlowID, migSubProtocol=migSubProtocol, migSequenceID=0x00, migVNFID=VNFID, migSessionID=migsessionID, networkInfo=networkInfo)

    # now, start looking which rules can be installed on which switches already:
    # we have a source and destination from the already existing flow
    # find the outHost (next NF hop)

    # install path for flow from dstSw to outHost
    inHost, outHost = dbConnect.searchSubFlow(host=migSrcSw.name, flowID=flowID, vnf=vnf)
    if inHost == "" or outHost == "":
        print 'inhost is: %s, outhost %s' % (inHost, outHost)
        # not sure what happens, but it is not good....h2 pin g
        return 

    outPath = netGraph.getShortestPathWithoutHost(migDstSw.name, outHost, migSrcSw.name)
    
    installStatus = installLabelPath(path=outPath,pkt=pkt,firstSwitch=str(migSrcSw.name),lastSwitch=str(outHost), sequence=1)
    ts = time()
    if installStatus == False:
        print "installing path failed somewhere."
        netFlows.rmMigHash(srcSwName=migSrcSw.name, dstSwName=migDstSw.name, flowID=flowID)
    else:
        # install the NF on the migDst:
        migDstSw.installVNF(pkt, vnf)
        # write to somewhere that this has been completed..
    print "Function time initFlowMigrate %f" % float(time() - tStart)
    print "initFlowMigrate stopped at %f" % float(time())
    netFlows.updateMigHash(srcSwName=migSrcSw.name, dstSwName=migDstSw.name, flowID=flowID, plusStatus=3, ts=tStart)
    # now the process should be started

def flowMigratetoForwardPhase(migSrcSw, migDstSw, migFlowID, VNFID):
    """
    This function is run if a '3c mig packet is received (ACK from update phase)'. Means the state is migrated and is getting updated
    First: check if the path has been installed. If this is completed, send the packet to go into the forward phase
    """
    tStart = time()
    print "flowMigratetoForwardPhase started at %f" % float(tStart)
    # find migration source switch (pkt comes from the migration destination)
    migsessionID = int(migSrcSw.swNum * 16 + migDstSw.swNum)
    networkInfo = getNetworkInFo(flowID=migFlowID,dstHost=migSrcSw.name)
    migSubProtocol = 0x3f
    migSequenceID = 0xffff

    
    dbMigStatus = netFlows.getMigHash(srcSwName=migSrcSw.name, dstSwName=migDstSw.name, flowID=migFlowID)
    while dbMigStatus < 4:
        if type(dbMigStatus) == type(int()):
            print "status %i not is goed!" % (int(dbMigStatus))
        if migSrcSw.stop == True:
            return
        # wait until dbMigStatus is 20 (entered the forward phase, meaning that the first rules are created)
        sleep(0.1)
        dbMigStatus = netFlows.getMigHash(srcSwName=migSrcSw.name, dstSwName=migDstSw.name, flowID=migFlowID)

    netFlows.updateMigHash(srcSwName=migSrcSw.name, dstSwName=migDstSw.name, flowID=migFlowID, plusStatus=7, ts=tStart)
    # let migsrcsw enter the forward phase
    
    migSrcSw.sendPacketOutMigration(flowID=migFlowID, migProcessFlowID=migDstSw.toFlowID, migSubProtocol=migSubProtocol, migSequenceID=migSequenceID, migVNFID=VNFID, migSessionID=migsessionID, networkInfo=networkInfo) 
    # now just wait for confirmation from migdst that it is receiving packets for the forward phase.

    print "Function time flowMigratetoForwardPhase %f" % float(time()-tStart)

def createLightPacket(flowID, swName):
    tStart = time()
    networkInfo = getNetworkInFo(flowID=flowID,dstHost=swName)
    if 'srcIP' in networkInfo and 'dstIP' in networkInfo and 'srcPort' in networkInfo and 'dstPort' in networkInfo and 'ipProtocol' in networkInfo and 'sequence' in networkInfo:
        srcIP = networkInfo['srcIP']
        dstIP = networkInfo['dstIP']
        srcPort = networkInfo['srcPort']
        dstPort = networkInfo['dstPort']
        ipProto = networkInfo['ipProtocol']
        sequenceID = networkInfo['sequence']

        pkt = controlPacket.controlPacketLight(flowID=flowID, srcIP=srcIP, dstIP=dstIP, srcPort=srcPort, dstPort=dstPort, ipProto=ipProto)
        print "Function time createlightpacket %f" % float(time()-tStart)
    return pkt, networkInfo
    

def flowMigrateFinish(migSrcSw, dstSwName, migFlowID, VNFID):
    tStart = time()
    # install a path from inHost to migDstSw
    vnf=dbConnect.returnVNFName(VNFID)
    print 'flowmigratefinish function aangeroepen. %s, %s, %s, %s' %(str(migSrcSw.name), str(dstSwName), str(migFlowID), str(VNFID))
    inHost, outHost = dbConnect.searchSubFlow(host=migSrcSw.name, flowID=migFlowID,vnf=vnf)
   
    if inHost == "" or outHost == "":
        print "Invalid inHost or outHost (flowMigrateFinish): %s and %s" % (str(inHost), str(outHost))
        return
        # probably because the rule installation is already done. Just forward packet to destination...
        #print "get path from inhost: %s to dst: %s without %s" % (inHost, dstSwName, migSrcSw.name)
    inPath = netGraph.getShortestPathWithoutHost(src=str(inHost), dst=str(dstSwName), removeHost=str(migSrcSw.name))
    #print "inhost: %s, path: %s" % (inHost, inPath)
    # retrieve networkInfo
    pkt, networkInfo = createLightPacket(flowID=migFlowID, swName=migSrcSw.name)

    #sID not important here, it is already installed...
    installStatus = installLabelPath(path=inPath,pkt=pkt,firstSwitch=str(inHost),lastSwitch=str(dstSwName), sequence=1)
    # above slow function, but we'll need to wait for this to happen
    if installStatus is not True:
        raise Exception("Rule installation for flowmigratefinish didn't succeed successfully")
    # change the table:
    tComplete = time()
    # update this table asynchronously
    updateThread = threading.Thread(target=dbConnect.updateNF, args=(migFlowID, migSrcSw.name, dstSwName))
    updateThread.start()
    #dbConnect.updateNF(flowID=migFlowID, oldDst=migSrcSw.name, newDst=dstSwName)
    # remove the hash for the migration
    # wait for a bit to clear everything... otherwise multiple migrations could be performed.
    #sleep(1)
    
    migStatus = netFlows.rmMigHash(srcSwName=migSrcSw.name, dstSwName=dstSwName, flowID=migFlowID)
    if (('tsInit' in migStatus) and ('tsForward' in migStatus) and 'tsFinish' in migStatus):
        tMigStart = migStatus['tsInit']
        tMigForward = migStatus['tsForward']
        tMigEnd = tComplete

        tMigUpPhase = tMigForward - tMigStart
        tMigForPhase = tMigEnd - tMigForward
        tMigTotal = tMigEnd -tMigStart
        print "Migration completed. Process took %f seconds. Update phase %s, forward %s" % (float(tMigTotal), float(tMigUpPhase), float(tMigForPhase))
        print "time between detection and mitigation is %s seconds" % float(float(tMigEnd) - float(migSrcSw.overloadDetected))
        with open('migrationtimes.txt', 'a+') as f:
            f.write("%f, %f, %f %f\n" % (float(tMigTotal), float(tMigUpPhase), float(tMigForPhase),float(float(tMigEnd) - float(migSrcSw.overloadDetected))))
            
        pktMon.addNewMigrationLine(srcSw=migSrcSw.name, dstSw=dstSwName, ts=tMigEnd, phase=60, flowID=migFlowID)    
    print "Function time flowmigratefinish %f" % float(time() - tStart)
    # doe nog ff sleepen om te snelle dingen te voorkomen
    sleep(5)
    migSrcSw.overloadDetected = False
    migSrcSw.overloading = 0
    
# now generate a packet
# remove old path from migsrc to dst 
# remove old path from src to migsrc

def flowMigrateUpdateRuleInstall(migSrcSw, migDstSw, migFlowID, VNFID):
    print 'Im in correct loop!!!!'
    # find old path

    # find differences to new path

    # define order to change path without doing harm

    # change path

def installLabelPath(path,pkt,firstSwitch,lastSwitch, sequence):
    if path == None:
        # find out if source and destination are hosts:
        # TODO this only works for host<=> host communications.
        raise Exception("Path None can't have a shortes route")
    
    if pkt.flowID == None:
        raise Exception("Flowid with id None can't be processed by installLabelPathFunction")
   
    # find services for flowID
    i = path.index(lastSwitch)
    while i >= 0:
        if netGraph.getHostAttr(path[i],"type") == "switch":
            s = switchFinder.findSwitch(path[i])
            installRules = []
            
            if s is not None:
                # do routing only if the path doesn't end with a switch. Do this until the last switch. 
                # This packet will send a new packetin when it has finished processing the packet.
                # doe als:
                
                if s.name != lastSwitch or path[-1] != str(lastSwitch):
                    #if s.name is not lastSwitch:
                    #print "installing route_flowID rule on switch %s" % s.name
                    installRule = {}
                    installRule["default_action"] = False
                    installRule["table_name"] = "route_flowID_tbl"
                    installRule["match_fields"] = {
                                                    "flowID.flowID": int(pkt.flowID),
                                                    }
                    installRule["action_name"] = "route_flowID"
                    installRule["action_params"] = {"outPort": int(netGraph.getLinkProperties(path[i],path[i+1])["port"])}
                    installRules.append(installRule)

                # only install this last rule when switching to a real destination host. Otherwise packetins don't work
                if (s.name == str(firstSwitch)) and (sequence == 0): # lastswitch bit added for single length paths. Is shouldn't set the flowID again.
                    #print "installing set_flowID rule on switch %s" % s.name
                    installRule = {}
                    installRule["default_action"] = False
                    installRule["table_name"] = "set_flowID_tbl"
                    installRule["match_fields"] = {
                                                    "ipv4.srcAddr": pkt.srcIP,
                                                    "ipv4.dstAddr": pkt.dstIP,
                                                    "ipv4.protocol": pkt.ip.p,
                                                    "port_metadata.srcPort": pkt.srcPort,
                                                    "port_metadata.dstPort": pkt.dstPort
                                                    }
                    installRule["action_name"] = "set_flowID"
                    installRule["action_params"] = {"flowid": pkt.flowID}
                    
                    installRules.append(installRule)
                # if the last step in the path is the last switch, do not install the last forwarding rule. 
                if (s.name == str(lastSwitch)) and (path[-1] != str(lastSwitch)):
                    #print "installing remove_flowID rule on switch %s" % s.name
                    installRule = {}
                    installRule["default_action"] = False
                    installRule["table_name"] = "remove_flowID_tbl"
                    installRule["match_fields"] = {
                                                    "flowID.flowID": int(pkt.flowID)
                                                    }
                    installRule["action_name"] = "remove_flowID"
                    installRule["action_params"] = {}
                    installRules.append(installRule)
            # at the end of this, install all rules to the switch
            s.installRulesOnSwitch(installRules)
        i -= 1
    
    return True

    
