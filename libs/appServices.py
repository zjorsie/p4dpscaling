serviceDict = {}

def addService(serviceName, data):
    global serviceDict

    if serviceName not in serviceDict.keys():
        serviceDict[serviceName] = {}
        serviceDict[serviceName]['data'] = data
        serviceDict[serviceName]['switchnames'] = []



def getServiceSwitches(serviceName):
    return serviceDict[serviceName]['switchnames']

def addServiceSwitch(serviceName, switchName):
    global serviceDict
    
    # exit if servicename does not exist or switchname is already in the active switch list
    if serviceName not in serviceDict.keys():
        return False    
    if switchName in serviceDict[serviceName]['switchnames']:
        return False
    
    serviceDict[serviceName]['switchnames'].append(switchName)
    print "servicedict: %s" % str(serviceDict)
    return True

def getDefaultFlowServices():
    return ['packetCounter']