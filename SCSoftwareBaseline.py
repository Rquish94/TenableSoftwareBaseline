
import datetime
import time
from tenable.io import AssetsAPI
from tenable.sc import TenableSC
from tenable.io import assets
securityCenter = TenableSC(')
#password = input('Please Enter Your Password')
securityCenter.login('','')
vuln2 = securityCenter.analysis.vulns()



def updateInv (number):
    fullInvUpdate = open('fullSoftwareInv', 'w')
    listone = []
    print('updating full inv \n')
    for vuln in securityCenter.analysis.vulns(('repositoryIDs', '=', '1'),('assetID', '=', number),('lastSeen','=','0:7'), tool='listsoftware', sort_field='name'):
        listone.append(vuln['name'])
    listTwo = list(set(listone))
    print('PRINTING LIST TWO')
    for i in listTwo:
        fullInvUpdate.write(i + '\n')
    fullInvUpdate.close()
	
	
def seperateKnownFromUnknown(chklist,newFile):
    #Adds Filtered names to a list
    print('creating list of good and bad \n')
    listOfGood = []
    fullinv = []
    inv = open('fullSoftwareInv', 'r')
    for i in inv:
        fullinv.append(i)
    inv.close()
    #If the word in "begins with" matches the beginning of the full list, add to "list of good software"
    for words in chklist:
        for listing in fullinv:
            if listing.startswith(str(words).replace('\n','')):
                listOfGood.append(listing)
                continue
            else:
                continue
    #Store The software inventory and the "list of good software" in sets and compare them (Giving you only the bad that is left)
    set1 = set(fullinv)
    set2 = set(listOfGood)
    result = (set1 - set2)
    moddedresult =(list(result))
    listOfBad = (str(sorted(moddedresult)).replace(r'\n','\n').replace("', '",'').replace("['",'').replace("']",''))
    #Prints the list of bad software
    n = open(newFile,'w')
    n.write(str(listOfBad).replace(r'\n','\n').replace("', '",''))
    n.close()
	
	
def compareFiles(recent,past):
    print('comparing lists to made bad output and remove dupes \n')
    z = (open('suspicious','w'))
    openrecent = open(recent,'r')
    openpast = open(past,'r')
    setrecent = set(openrecent)
    setpast = set(openpast)
    output = (setpast - setrecent)
    for i in output:
        z.write(str(i.replace('\n','')+'\n'))
    z.close()
	
	
def mainFunction(type):
    filter = []
    if type.lower() == 'wd':
        number = '130'
        newFile = 'Questionable Desktop '+datetime.datetime.now().strftime("%m-%d-%y")
        baseline = 'questionable Desktop Baseline 1-28-19--2-1-19'
        beginsList = open('beginsWith', 'r')
        for n in beginsList:
            filter.append(n)
        beginsList.close()
    elif type.lower() == 'ws':
        number = '131'
        newFile = 'Questionable Windows Server '+datetime.datetime.now().strftime("%m-%d-%y")
        baseline = 'Questionable Windows Server Baseline 02-15-19'
        beginsList = open('beginsWith', 'r')
        for n in beginsList:
            filter.append(n)
        beginsList.close()
    elif type.lower() == 'l':
        number = '129'
        newFile = 'Questionable Linux '+datetime.datetime.now().strftime("%m-%d-%y")
        baseline = 'Questionable Linux Baseline 02-15-19'
        linuxFilter = open('linuxBeginsWith', 'r')
        for n in linuxFilter:
            filter.append(n)
        linuxFilter.close()
    elif type.lower() == 'all':
        print('\nProcessing Windows Desktop\n')
        mainFunction('wd')
        time.sleep(5)
        print('-'*40)
        print('\nProcessing Windows Server\n')
        mainFunction('ws')
        time.sleep(5)
        print('-' * 40)
        print('\nProcessing Linux\n')
        mainFunction('l')
        exit()

    else:
        print('Please pick wd for windows desktop, ws for windows server, l for linux\n')
        exit()

    updateInv(number)
    seperateKnownFromUnknown(filter,newFile)
    compareFiles(baseline,newFile)

    openpage = open('suspicious', 'r')
    for i in openpage:
        for vuln in securityCenter.analysis.vulns(('pluginText', '=', str(i)), tool='vulnipsummary', sort_field='name'):
            group = str(vuln['hosts'][0]['iplist']).split(',')
            print(str('Software Name: ' + i + '  List of IPs: ' + vuln['hosts'][0]['iplist'] + '  Count: ' + str(
                len(group)) + '\n'))


mainFunction('all')