from time import time
from time import sleep
import math
import os
import libs.dbConnect as dbConnect
#from libs.p4runtime_lib.switch import findSwitch
flowDict = {}
first = True

margin = 10 # percent
marginCapacity = 25 # percent load

def addReading(flowID, ts, nrPackets, sw):
    global first
    global flowDict
    # this function calculates average rate since last measurement
    # do readable flowID's
    if type(flowID) != type(hex):
        flowID = hex(flowID)
    # make structure (per-switch)
    # do delay:
    sleep(sw.controlPlaneDelay)
    if not (flowID in flowDict):
        makeflowDictStructure(flowID, sw.name)
    tsOld = flowDict[flowID]['lastTs']
    oldRate = flowDict[flowID]['curRate']

    # for first occurence, only store the ts
    if tsOld != 0:
        dT = float(float(ts) - float(tsOld)) / 1000000

        newRate = math.ceil(float(nrPackets) / float(dT))
        flowDict[flowID]['curRate'] = newRate
        if ((float(dT) < float(1-float(margin/100)) or float(dT) > float(1+float(margin/100)))) and oldRate is not newRate:      
            # we are changing the default parameter
            # new value ~ rate
            # prepare table rule for installation to do this  
            changeFlowIDMonitoringFreq(flowID, newRate, sw)

            
    # always store the TS. No rates will be calculated and no changes will occur
    fileDir = os.path.abspath("./Data/avgRate")
    if not os.path.isdir(fileDir):
        os.makedirs(fileDir)

    fileName = os.path.join(fileDir, "avgRate-%s.txt" % sw.name)
    if tsOld != 0:
        if first == True:
            try:
                os.system("rm %s/avgRate.*" % fileDir)
            except:
                pass
            first = False
            flag = "w+"
        else:
            flag = "a+"
        with open(os.path.join(fileDir, fileName), flag) as f:
            f.write("%f %s %i\n" %(float(ts), str(flowID), int(newRate)))

    # update information
    flowDict[flowID]['lastTs'] = ts
    flowDict[flowID]['ts'] = float(time())

def makeflowDictStructure(flowID, swName):
    global flowDict
    flowDict[flowID] = {}
    flowDict[flowID]['lastTs'] = 0
    flowDict[flowID]['curRate'] = 0
    flowDict[flowID]['ts'] = float(time())
    flowDict[flowID]['threshold'] = 10 # default. also defined in P4
    flowDict[flowID]['readSw'] = swName
    # flowDict[flowID][swName]['rates'] = {}
    # flowDict[flowID][swName]['rates']['ts'] = []
    # flowDict[flowID][swName]['rates']['rate'] = []

def changeFlowIDMonitoringFreq(flowID, newRate, sw):
    global flowDict
    #print "Changing monitoring speed for flowID %s to %d" % (str(flowID), newRate)
    if newRate == 0:
        newRate = 1
    installRules = []
    installRule = {}
    installRule['default_action'] = False
    installRule["table_name"] = "readPacketStats_table"
    installRule['match_fields'] = {
                                    "flowID.flowID": int(flowID,16),
                                }
    installRule["action_name"] = "readPacketStats"
    installRule["action_params"] = {
                                    "THRESHOLD": int(abs(newRate))
                                }
    installRules.append(installRule)
    flowDict[flowID]['threshold'] = int(newRate)
    sw.installRulesOnSwitch(installRules)
    
def getSwitchLoad(swName):
    # find which flows that have some vnf performed on the switch
    flowIDs = flowIDDictToHexList(dbConnect.getAllSwitchFlows(swName))
    #print flowIDs
    # convert flowIDs to hex strings:
    # find the switch load
    
    swLoadDict = getLoadFlowID(flowIDs)
    #print swLoadDict
    # calculate the sum
    swLoad = 0
    for flowID in swLoadDict.keys():
        swLoad += int(swLoadDict[flowID])
    return swLoad

def getSwitchTopLoads(swName, num=10):
    # retrieve flows for switch:
    flowIDs = flowIDDictToHexList(dbConnect.getSwitchFlows(sw=swName, len=num))
    flowStats = {}
    
    flowStats = getLoadFlowID(flowIDs)
    
    sortedFlowStats = sorted(flowStats.items(), key=lambda x: x[1], reverse=True)
    return sortedFlowStats

def flowIDDictToHexList(flowIDDictList):
    flowIDList = []
    for flowIDDict in flowIDDictList:
        flowIDList.append(hex(flowIDDict['flowID']))
    return flowIDList

def getLoadFlowID(flowIDs):
    """
    This function gives the summed flow load for a given set of flowIDs. 
    These flowIDs should be given in a list
    """
    if type(flowIDs) != type([]):
        print 'give list to getLoadFlowID function!'
        return {}
    
    loadDict = {}
    for flowID in flowIDs:
        loadDict[flowID] = getFlowLoad(flowID)
    return loadDict

def getFlowLoad(flowID):
    """
    This function calculates the estimated rate of the flow

    The worst-case load is calculated as:
    threshold / age of the digest

    For short time periods this would lead to huge numbers.
    Therefore, then the last average rate is used.
    """
    flowID = str(flowID)
    try:
        # NO STATS AVAILABLE (YET)
        if flowID not in flowDict.keys():
            return 0
        if 'ts' not in flowDict[flowID].keys():
            return 0

        # we know it is available

        rateAge = float(float(time()) - float(flowDict[flowID]['ts']))
        if float(rateAge) < (float(1.5)):
            # flowload is very specific
            return int(flowDict[flowID]['curRate'])
        else: 
           
            # flowload is not very specific
            # calculate worst-case averate
            # no update has been received. 
            #
            # worst-case load is now threshold / rateAge (otherwise, an update would have been received)
            return int(float(flowDict[flowID]['threshold']) / float(rateAge))
    except Exception as e:
        print("iets foutgegaan in getFlowLoad")
        print(e)

            








