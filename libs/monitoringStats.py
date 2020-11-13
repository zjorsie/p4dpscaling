import matplotlib
matplotlib.use('Agg')
import time
import matplotlib.pyplot as plt
from mpl_toolkits.axes_grid1 import host_subplot
import mpl_toolkits.axisartist as AA
from timeit import default_timer as timer
import numpy as np
import copy
import os

import libs.lockGraphs
import libs.dbConnect as dbConnect

pktMon = None

monFileBase = "Data/packetstatsraw"
monDigestFileBase = "Data/digeststatsRaw"
filename = "Queuestats"
firstLog = True
migFilename = 'migration.txt'
migDir = "Data/migrationData/"
firstMig = True
switches = ['s1', 's2', 's3', 's4']
migMonitorPath = "Data/migrationData"
migMonitorFile = "migrationUpdates.txt"
rateFile = "rates-"
firstMigMonitor = True
firstRate = True
curSwUsage = {}

class pktMonPacket:
    def __init__(self):
        self.pktStat = {}
        self.curReading = {}
        self.switch_type = None 
        self.timerStart = timer()
        self.stop = False

    def stopThread(self):
        self.stop = True

def initpktMon():
    global pktMon
    if pktMon == None:
        pktMon = pktMonPacket()


def stoppktMon():
    pktMon.stopThread()    

def printInfo():
    print pktMon.pktStat
    print pktMon.switch_type
    print pktMon.timerStart

def addNewMigrationLine(srcSw, dstSw, ts, phase, flowID, tsRel=None):
    global firstMig
    try: 
        flowID = int(flowID,16)
    except:
        flowID = int(flowID)
    fname = os.path.join(migDir, migFilename)
    
    if not os.path.isdir(migDir):
        os.makedirs(migDir)

    if firstMig == True:
        if os.path.isfile(fname):
            os.remove(fname)
        firstMig = False

    with open(fname, 'a') as f:
        if tsRel == None:
            f.write("%s %s %i %f %i\n" % (str(srcSw), str(dstSw), int(phase), float(ts), int(flowID)))
        else:
            f.write("%s %s %i %f %i %f\n" % (str(srcSw), str(dstSw), int(phase), float(ts), int(flowID), float(tsRel)))

def addpktSwitch(s_name, s_type, categories):
    global pktMon
    
    pktMon.pktStat[s_name] = {}
    pktMon.pktStat[s_name]['type'] = str(s_type)
    pktMon.pktStat[s_name]['pktStats'] = {}
    pktMon.pktStat[s_name]['pktStats']['lastTs'] = float(0)
    pktMon.pktStat[s_name]['pktStats']['total'] = float(0)
    pktMon.pktStat[s_name]['pktStats']['packetCounter'] = float(0)
    pktMon.pktStat[s_name]['pktStats']['proxyStateless'] = float(0)
    # delete old rate files:
    fullFName = rateFile + str(s_name) + '.txt'
    fullFile = os.path.join(migDir, fullFName)

    if firstRate == True:
        if not os.path.isdir(migDir):
            os.makedirs(migDir)
        if os.path.isfile(fullFile):
            os.remove(fullFile)

def addMigPktReading(s_name, sequenceID, VNFID, sessionID, flowID, ts_u):
    global firstMigMonitor
    tPath = os.path.join(migMonitorPath, migMonitorFile)
    if not os.path.isdir(migMonitorPath):
        os.path.makedirs(migMonitorFile)
    if firstMigMonitor == True:
        firstMigMonitor = False
        if os.path.isfile(tPath):
            os.remove(tPath)
    # now write to logfile
    with open(tPath, 'a') as f:
        f.write("%s %i %i %i %i %i\n" % (str(s_name), int(sequenceID), int(VNFID), int(sessionID), int(flowID), int(ts_u)))

def addpktDigestReading(s_name, enqdepth, deqdepth, tqueue, ts):
    global firstLog

    if firstLog == True:
        if os.path.isfile(filename + '-s1.txt'):
            os.remove(filename + '-s1.txt')
        if os.path.isfile(filename + '-s2.txt'):
            os.remove(filename + '-s2.txt')
        if os.path.isfile(filename + '-s3.txt'):
            os.remove(filename + '-s3.txt')
        firstLog = False    
    
    qfile = open(filename + '-' + str(s_name) + '.txt', 'a+')
    qfile.write("%s %i %i %f %f\n" % (str(s_name), int(enqdepth), int(deqdepth), float(tqueue), float(ts)))
    qfile.close()

def getSwitchLoad(s_name, vnf='total'):
    try:
        if vnf not in ['packetCounter', 'proxyStateless']:
            vnf = 'total'
        return float(pktMon.pktStat[str(s_name)]['pktStats'][str(vnf)])
    except:
        raise Exception("Unknown NF or switch (getSwitchload)")


def addPktSwitchReading(s_name, pktsDict, ts):
    """
        This function will add a new reading to the 'curreading' dict of the packetmonitor.
        built as:
        pktMon[s_name]['pktStats'][total]
        pktMon[s_name]['pktStats'][vnf1]
        pktMon[s_name]['pktStats'][vnf..]
        pktMon[s_name]['pktStats'][lastTs]

    """
    global pktMon
    global firstRate
    if s_name in pktMon.pktStat.keys():
        # it is created.
        dT = float(ts) - float(pktMon.pktStat[s_name]['pktStats']['lastTs']) 
        if float(float(pktsDict['general'])/float(dT)) != 0:
            pktMon.pktStat[s_name]['pktStats']['total'] = float(float(pktsDict['general'])/float(dT))
        pktMon.pktStat[s_name]['pktStats']['lastTs'] = float(ts)
        pktMon.pktStat[s_name]['pktStats']['packetCounter'] = float(float(pktsDict['packetCounter'])/float(dT))
        pktMon.pktStat[s_name]['pktStats']['proxyStateless'] = float(float(pktsDict['proxyStateless'])/float(dT))
        pktMon.pktStat[s_name]['pktStats']['migration'] = float(float(pktsDict['migrate'])/float(dT))

    # write rates to file for graph generation:

    
        fullFName = rateFile + str(s_name) + '.txt'
        fullFile = os.path.join(migDir, fullFName)

        if firstRate == True:
            if not os.path.isdir(migDir):
                os.makedirs(migDir)
            if os.path.isfile(fullFile):
                os.remove(fullFile)
            firstRate = False

        with open(fullFile, 'a+') as f:
            f.write("%f %f %f %f %f\n"%(float(ts), float(pktMon.pktStat[s_name]['pktStats']['total']), float(pktMon.pktStat[s_name]['pktStats']['packetCounter']), float(pktMon.pktStat[s_name]['pktStats']['proxyStateless']), float(pktMon.pktStat[s_name]['pktStats']['migration'])))

class Measurements(object):
    def __init__(self):
        self.measurements = []
        self.converttoSec = 1000000000
        self.conn = libs.dbConnect.localInitDB()
        for l in libs.dbConnect.readFlowLogGraph():
            for attr in ['flowID', 'rsw', 'tsw', 'rts', 'tts', 'sequenceID', 'VNFID', 'subProtocol']:
                if not hasattr(l, attr):
                    continue
            if l['sequenceID'] > 1:
                self.measurements.append(logMigrate(flowID=l['flowID'], rsw=l['rsw'], tsw=l['tsw'], rts=l['rts'], tts=l['tts'], sequenceID=l['sequenceID'], VNFID=l['VNFID'], subProtocol=l['subProtocol']))

class logMigrate(object):
    def __init__(self, flowID, rsw, tsw, rts, tts, sequenceID, VNFID, subProtocol):
        self.rts = rts
        self.tts = tts
        self.abstime = abs(tts - rts)
        self.sequenceID = sequenceID
        self.recvSw = rsw
        self.sendSw = tsw
        self.VNFID = VNFID
        self.subProtocol = pktTypsubProtocole