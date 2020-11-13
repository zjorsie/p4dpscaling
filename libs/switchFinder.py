allSwitches = []

def findSwitch(name):
    for s in allSwitches:
        if s.name == name:
            return s
    print("findswitch %s not found" % name)

def addSwitch(sw):
    global allSwitches
    allSwitches.append(sw)

def findSwitchBynumber(number):
    for s in allSwitches:
        if int(s.swNum) == int(number):
            return s
    print("findSwitchBynumber %s not found" % name)
