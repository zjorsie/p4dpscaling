import time

lock = {}
lock['ts'] = time.time()
lock['status'] = False

def getStatus(checkOnly = False):
    global lockGraphs

    if lock['status'] == True:
        if lock['ts'] < time.time() - 10:
            # long time ago. Just claim it's false:
            if checkOnly == False:
                setLock()
            return False
        return True
    else:
        setLock()
        return False
            
def clearLock():
    global lock
    lock['ts'] = time.time()
    lock['status'] = False

def setLock():
    global lock
    lock['ts'] = time.time()
    lock['status'] = True

    
