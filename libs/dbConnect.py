import sqlite3
import time
import copy
import threading
timinglogfile = open("timelogs.log","w+")

safeflowTable = {}

dbInsertQueue = []
threadConn = {}
installedRules = {}
def getThreadConnection():
    global threadConn
    threadID = threading.currentThread().ident

    if threadID not in threadConn.keys():
        # setup a new connection
        threadConn[threadID] = localInitDB()
        #print("opening new connection to database. Total number of connections: %i" % int(len(threadConn.keys())))
    
    return threadConn[threadID]
def createEmptyDB():
    
    try:
        curCon = getThreadConnection()
        c = curCon.cursor()
        # create main database scheme:
        c.execute("SELECT name FROM sqlite_master WHERE type='table';")

        for x in c.fetchall():
            c.execute('DROP TABLE %s;' % (x[0]))
            print "table %s deleted" % x[0]

        c.execute("CREATE TABLE flowTable (flowID UNSIGNED BIG INT NOT NULL, srcHost text NOT NULL, dstHost text NOT NULL, vnf text, sequence INT NOT NULL,lastUsed text, srcIP text NOT NULL, srcPort int NOT NULL,ipProtocol int NOT NULL, dstIP text NOT NULL, dstPort int not null, PRIMARY KEY (flowID,sequence));")
                # DstSw is the switch that performs the service
        c.execute("CREATE TABLE service_proxyStateless (srcIP text NOT NULL, dstIP text NOT NULL, newDstIP text NOT NULL, newDstMAC text NOT NULL);")
        #c.execute("CREATE TABLE installedRules (sID text NOT NULL, table_name text NOT NULL, action_params blob, action_name text NOT NULL, match_fields blob, default_action text NOT NULL);")

        c.execute("CREATE TABLE VNF (vnfName text NOT NULL, srcIP text NOT NULL, dstIP text NOT NULL, srcPort text NOT NULL, dstPort text NOT NULL, ipProtocol text NOT NULL, prio integer NOT NULL, PRIMARY KEY(srcIP, dstIP, prio));")
        c.execute("CREATE TABLE flowMigrate (flowID UNSIGNED BIG INT NOT NULL, srcSw text NOT NULL, dstSw text NOT NULL, migStatus text NOT NULL, ruleUpdate INT);")
        c.execute("CREATE TABLE flowLogger (flowID UNSIGNED BIG INT NOT NULL, ts UNSIGNED BIG INT NOT NULL, recvSw text NOT NULL, sequenceID INT NOT NULL, VNFID int NOT NULL, subProtocol text NOT NULL, PRIMARY KEY(flowID, ts));")
        # Save (commit) the changes
        curCon.commit()
        c.close()

    except:
        print "Something has happened during execution of this function"
        return False
    return True

def addVNF(vnfName, srcIP = 'ALL', dstIP = 'ALL', srcPort = 'ALL', dstPort = 'ALL', ipProtocol = 'ALL', prio = int(1)):
    curCon = getThreadConnection()
    c = curCon.cursor()
    # check if service already exists:
    c.execute("SELECT srcIP from VNF where srcIP=? and dstIP=? and srcPort=? and dstPort = ? and ipProtocol = ?;", (str(srcIP), str(dstIP), str(srcPort), str(dstPort), str(ipProtocol)))
    res = c.fetchall()
    if len(res) > 0:
        print "VNF already exists"
        return
    #print 'function addVNF %s' % (vnfName)
    c.execute("SELECT MAX(prio) as prio from VNF where srcIP=? and dstIP=? and srcPort=? and dstPort = ? and ipProtocol = ?;", (str(srcIP), str(dstIP), str(srcPort), str(dstPort), str(ipProtocol)))
    result = parseResults(c)[0]

    if hasattr(result, 'prio'):
        if int(prio) <= int(result['prio']):
            if prio > 0:
                prio = result['prio'] + 1
            if prio <= 0:
                if prio >= result['prio']:
                    prio = result['prio'] - 1
    c.execute("INSERT INTO VNF (vnfName, srcIP, dstIP, srcPort, dstPort, ipProtocol, prio) VALUES (?,?,?,?,?,?,?);", (str(vnfName), str(srcIP), str(dstIP), str(srcPort), str(dstPort), str(ipProtocol), int(prio)))
    curCon.commit()
    c.close()

    print "Added VNF %s from %s to %s" %(vnfName, srcIP, dstIP)


def getFlowVNFS(srcIP, dstIP, srcPort = None, dstPort = None, ipProtocol=None):    
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("SELECT vnfName, prio from VNF where srcIP IN ('ALL', ?) and dstIP IN ('ALL', ?) and srcPort IN ('ALL', ?) and dstPort IN ('ALL', ?) and ipProtocol IN ('ALL', ?) ORDER BY prio ASC;", (str(srcIP), str(dstIP), str(srcPort),str(dstPort), str(ipProtocol)))
    resultList = parseResults(c)
    c.close()

    return resultList
    # find all normal rules

def getVNFSwitch(vnf):
    #print("Getting all switches that run VNF %s" % str(vnf))
    curCon = getThreadConnection()
    c = curCon.cursor()
    result = []
    c.execute("SELECT DISTINCT dstHost from flowTable WHERE vnf=?", (vnf,))
    rawResult = parseResults(c)
    print rawResult
    for rawRow in rawResult:
        result.append(rawRow["dstHost"])
    return result
    
def getSwitchVNFS(sw):
    #print("Getting all VNFS that are active on the switch")
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("SELECT distinct(vnf) FROM flowTable WHERE dstHost = ?;", (sw,))
    result = parseResults(c)
    c.close()
    return result

def getSwitchFlows(sw, len=10):
    

    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("SELECT distinct(flowID) FROM flowTable WHERE dstHost = ? and vnf NOT IN ('None') LIMIT ?;", (sw,len))
    result = parseResults(c)

    c.close()
    return result

def getAllSwitchFlows(sw):
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("SELECT distinct(flowID) FROM flowTable WHERE dstHost = ? AND vnf NOT IN ('None');", (str(sw),))
    result = parseResults(c)

    c.close()
    return result


def searchFlowMigrate(flowID, srcSw, count = True):
    #print 'searchFlowMIgratefunctie'
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("SELECT count(*) as count FROM `flowMigrate` WHERE `flowID`= ? AND `srcSw` = ?;", (int(flowID), str(srcSw)))
    result = parseResults(c)
    c.close()
    if count == True:
        return result[0]['count']
    else:
        return result

def searchRawFlowMigrate(flowID, dstSw):
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("SELECT * FROM flowMigrate WHERE flowID= ? AND srcSw = ?;", (int(flowID), str(dstSw)))
    result = parseResults(c)
    if len(result) > 0:
        return result[0]
    else:
        return []
    c.close()

    return result

def addFlowMigrate(flowID, srcSw, dstSw, migStatus):
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("INSERT INTO flowMigrate (flowID, srcSw, dstSw, migStatus) VALUES (?,?,?,?);", (int(flowID), str(srcSw), str(dstSw), str(migStatus)))
    curCon.commit()
    c.close()

def searchFlowMigrateDstHost(flowID, srcSw):
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("SELECT dstSw from flowMigrate where flowID=? and srcSw=?", (int(flowID), str(srcSw)))
    result = parseResults(c)
    c.close()
    if len(result) < 1:
        return None
    return result[0]['dstSw']

def updateFlowMigrate(flowID, srcSw, dstSw, migStatus):
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("UPDATE flowMigrate SET migStatus=? WHERE flowID=? AND srcSw=? and dstSw=?", (str(migStatus), int(flowID), str(srcSw), str(dstSw)))
    curCon.commit()
    c.close()

def updateNF(flowID, oldDst, newDst):
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("UPDATE flowTable SET dstHost=? WHERE flowID=? AND dstHost=?", (str(newDst), int(flowID), str(oldDst)))
    c.execute("UPDATE flowTable SET srcHost=? WHERE flowID=? AND srcHost=?", (str(newDst), int(flowID), str(oldDst)))
    curCon.commit()
    c.close()
def flowMigrateUpdateRuleInstall(flowID, srcSw, dstSw, ruleUpdate):
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("UPDATE flowMigrate SET ruleInstall=? WHERE flowID=? and srcSw=? and dstSw?", (int(ruleUpdate), int(flowID), str(srcSw), str(dstSw)))
    curCon.commit()
    c.close()
def searchFlowTable(flowID, srcIP, srcPort, ipProtocol, dstIP, dstPort, vnf):
    # fields:
    # - flowID BIG INT
    # - srcHost text
    # - dstHost text
    # - vnf text
    # - sequence int
    # - lastUsed text
    # - srcIP text
    # - srcPort int
    # - ipProtocol int
    # - dstIP  text
    # - dstPort int
    ans = []
    try:
        curCon = getThreadConnection()
        c = curCon.cursor()
        c.execute("SELECT * FROM flowTable where flowID = ? and srcIP=? and srcPort=? and ipProtocol=? and dstIP=? and dstPort=? and vnf=?;",(int(flowID), str(srcIP), int(srcPort), int(ipProtocol),str(dstIP), int(dstPort), str(vnf)))
        ans = parseResults(c)
    except Exception as e:
        print "Something went wrong when searching flowtable;"
        print e
        return []

    c.close()
    return ans

def addFlowTableEntryDB(flowID, srcHost, dstHost, vnf, srcIP, srcPort, ipProtocol, dstIP, dstPort, sequenceID):
    if srcHost != dstHost:
        curCon = getThreadConnection()
        c = curCon.cursor()
    
        try:
            c.execute("INSERT INTO flowTable (flowID, srcHost, dsthost, vnf, sequence, srcIP, srcPort, ipProtocol, dstIP, dstPort) VALUES (?,?,?,?,?,?,?,?,?,?);",(int(flowID), str(srcHost), str(dstHost), str(vnf), int(sequenceID), str(srcIP), int(srcPort), int(ipProtocol), str(dstIP), int(dstPort)))
        except Exception as e:
            print "error with addFlowTableEntryDB function"
            print "flowiD: %i %i" % (int(flowID), int(sequenceID))
            print e
        curCon.commit()
        c.close()

def addFlowTableEntry(flowID, srcHost, dstHost, vnf, srcIP, srcPort, ipProtocol, dstIP, dstPort):
    global safeflowTable
    # fields:
    # - flowID BIG INT
    # - srcHost text
    # - dstHost text
    # - vnf text
    # - sequence int
    # - lastUsed text
    # - srcIP text
    # - srcPort int
    # - ipProtocol int
    # - dstIP  text
    # - dstPort int
    e = None
    skipDB = False
    if str(flowID) in safeflowTable.keys():
        if safeflowTable[str(flowID)][-1] != str(dstHost):
            # add this host to the list if it doesnt already exist
            skipDB = True
            safeflowTable[str(flowID)].append(str(dstHost))
    else:
        safeflowTable[str(flowID)] = [str(dstHost)]
    sequenceID = int(len(safeflowTable[str(flowID)]) - 1)
    #if skipDB == False:
    dbThread = threading.Thread(target=addFlowTableEntryDB, args=(flowID, srcHost, dstHost, vnf, srcIP, srcPort, ipProtocol, dstIP, dstPort, sequenceID))
    dbThread.start()
        # query if flowID already is in database. search for it and order descending: the first result is the highest current number
    return sequenceID   
    
def searchProxyStateless(srcIP, dstIP):
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("SELECT srcIP, dstIP, newDstIP, newDstMAC FROM service_proxyStateless where srcIP=? and dstIP=?;", (srcIP, dstIP))

    # should be only 1 result:
    resultList = parseResults(c)
    c.close()

    return resultList

def addProxyStateless(srcIP, dstIP, newDstIP, newDstMAC):
    try:
        curCon = getThreadConnection()
        c = curCon.cursor()
        c.execute("INSERT INTO service_proxyStateless (srcIP, dstIP, newDstIP, newDstMAC) VALUES (?,?,?,?);",(srcIP, dstIP, newDstIP, newDstMAC))
        curCon.commit()
        c.close()
    except:
       raise Exception ("addProxyStateless")

def returnProxyID(dstHost, flowID):

    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("SELECT vnf from flowTable where dstHost = ? and flowID = ?;", (str(dstHost), int(flowID)))
    entry = parseResults(c)[0]
    c.close()
    if 'vnf' in entry.keys():
        if entry['vnf'] == 'proxyStateless':
            return 0x00
        if entry['vnf'] == 'packetCounter':
            return 0x0f
    return 0xff


def returnVNFName(vnfID):
    if vnfID == int(0x0f):
        return 'packetCounter'
    elif vnfID == int(0x00):
        return 'proxyStateless'
    return 0xff

def returnVNFID(vnfName):
    if vnfName == 'packetCounter':
        return 0x0f
    elif vnfName == 'proxyStateless':
        return 0x00
    return 0xff

def parseResults(c):
    # Tested
    try:
        result = [dict(row) for row in c.fetchall()]
    except Exception as e:
        print("Exception parsing results")
        print(e)
    
    return result
    

def getNetworkInFo(flowID, dstHost):
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("SELECT srcIP, srcPort, dstIP, dstPort, ipProtocol, sequence from flowTable where flowID=? and dstHost=?;",(int(flowID), str(dstHost)))
    results = parseResults(c)
    c.close()
    if len(results) > 0:
        return results[0]
    else:
        return []

def getMigSrcSw(flowID, VNFID):
    curCon = getThreadConnection()
    c = curCon.cursor()
    VNFName = returnVNFName(VNFID)
    c.execute("SELECT * FROM flowTable where flowID='%i' and vnf='%s';" % (int(flowID), str(VNFName)))
    results = parseResults(c)
    c.close()
    if len(results) > 0:
        return results[0]
    else:
        return None

def searchVNFFlows():
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("SELECT flowID from flowTable where vnf != 'None';")
    results = parseResults(c)
    c.close()
    return results

def searchVNFSbyFlow(flowID):
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("select vnf from flowTable where vnf != 'None' AND flowID = ?;", (int(flowID),))
    results = parseResults(c)
    c.close()
    resultList = []
    for x in results:
        resultList.append(x['vnf'])
    return resultList

def searchSubFlow(host, flowID, vnf):
    curCon = getThreadConnection()
    c = curCon.cursor()
    
    if type(host) != type(str()):
        if hasattr(host, 'name'):
            h = host.name
        else:
            h = str(host)
    else:
        h = str(host)
    
    try: 
        flowID = int(flowID)
    except:
        flowID = int(flowID,16)
        
    #print 'searchsubflow %s %s %s' % (str(h), str(flowID), str(vnf))
    c.execute("SELECT srcHost, sequence FROM flowTable where dstHost=? AND flowID=? AND vnf=?", (str(h), int(flowID), str(vnf)))
    resultList = parseResults(c)
    if len(resultList) == 0:
        return "",""
    else:
        srcHost = str(resultList[0]['srcHost'])

    c.execute("SELECT dstHost FROM flowTable where srcHost=? AND flowID=? AND sequence=?", (str(h), int(flowID), int(int(resultList[0]['sequence']) + 1)))
    resultList = parseResults(c)
    c.close()

    if len(resultList) == 0:
        dstHost = ""
    else:
        dstHost = str(resultList[0]['dstHost']) # only one result, since dst/flowID is unique in DB
    
    return srcHost, dstHost
        
            
def getVNFSwitchFlowIDs(srcHost, vnfName):
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("SELECT flowID from flowTable where srcHost=? and vnfName=?", (srcHost, vnfName))
    resultList = parseResults(c)
    c.close()
    return resultList

def addInstalledRule(sID, table_name, action_name, default_action=False, match_fields="NULL", action_params="NULL"):
#CREATE TABLE installedRules 
# swID text NOT NULL, 
# table_name text NOT NULL, 
# action_params text, 
# action_name text NOT NULL, 
# match_fields text, 
# default_action text NOT NULL")
    global installedRules
    if sID not in installedRules.keys():
        installedRules[sID] = {}

    ruleHash = hash((str(table_name), str(action_name), str(default_action), str(match_fields)))
    installedRules[sID][str(ruleHash)] = str(action_params)

def getInstallRule(sID, table_name, action_name, default_action=False, match_fields={}):
    # calculate hash:
    if sID not in installedRules.keys():
        return []
    ruleHash = hash((str(table_name), str(action_name), str(default_action), str(match_fields)))

    if str(ruleHash) in installedRules[sID].keys():
        return installedRules[sID][str(ruleHash)]
    else:
        return []

def initDBCon():
    tStart = time.time()
    try:
        curCon = getThreadConnection()
        c = curCon.cursor()
        print 'DB connect time was %f' % float(time.time() - tStart)
    except:
        print "there was an error opening the database"
        return False
    return True

def localInitDB():
    try:
        dbcon = sqlite3.connect('mycontroller.db', check_same_thread=False)
        dbcon.row_factory = sqlite3.Row
    except:
        print "there was an error opening the database"
        return None 
    return dbcon

def closeDB(conn):
    conn.close()

def closeAllDBConns():
    for threadID in threadConn.keys():
        closeDB(threadConn[threadID])
    timinglogfile.close()
    print "Database has been closed"

def addFlowLog(flowID, ts, recvSw, sequenceID, VNFID, subProtocol):
    VNFstr = returnVNFName(VNFID)
    if False:
        # flowLogger (flowID UNSIGNED BIG INT NOT NULL, ts blob, recvSw text NOT NULL, sequenceID INT NOT NULL, VNFID int NOT NULL)
        curCon = getThreadConnection()
        c = curCon.cursor()
        #print 'added flowid %d, ts %d, recvSw %s, sequenceID %d, VNFID %s, subProtocol %s'% (int(flowID), int(ts), str(recvSw), int(sequenceID), str(VNFstr), str(subProtocol))
        try:
            c.execute("INSERT INTO flowLogger (flowID, ts, recvSw, sequenceID, VNFID, subProtocol) VALUES (?,?,?,?,?,?);", (int(flowID), int(ts), str(recvSw), int(sequenceID), str(VNFstr), str(subProtocol)))
            curCon.commit()
        except Exception as e: 
            print("error storing in database!")
            print e
        c.close()
    else:
        # store the data in a file.
        timinglogfile.write("%d,%d,%s,%d,%s,%s\n" % (int(flowID), int(ts), str(recvSw), int(sequenceID), str(VNFID), str(subProtocol)))
        timinglogfile.flush()
        
def getVNFFlowIDs(vnfName):
    curCon = getThreadConnection()
    c = curCon.cursor()
    try:
        c.execute("Select flowID from flowTable where vnfName = ?", (str(vnfName)))
        result = parseResults(c)
        c.close()
    
        return result
    except Exception as e:
        print("Error getting flowIDs for VNF")
        print e
        return []

def readFlowLog(filter):
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("Select * from flowLogger where %s;" % str(filter))
    result = parseResults(c)
    c.close()
    return result

def readFlowLogGraph():
    curCon = getThreadConnection()
    c = curCon.cursor()
    c.execute("""SELECT a.flowID as flowID, a.sequenceID as sequenceID, a.VNFID as VNFID, a.subProtocol as subProtocol, a.ts as rts, b.ts as tts, a.recvSw as rsw, b.recvSw as tsw
                FROM flowLogger as a, flowLogger as b 
                WHERE a.flowID = b.flowID
                AND a.VNFID = b.VNFID
                AND a.recvSw != b.recvSw
                AND a.sequenceID = b.sequenceID
                AND a.subProtocol = b.subProtocol
                AND a.ts <= b.ts;""")
    result = parseResults(c)
    c.close()
    return result

