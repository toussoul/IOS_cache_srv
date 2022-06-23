"""

	Note:
		Need To install :
			brewhome
			python3
			pip 
			nmap
			arp-scan
		PIP install:
			threading
			datetime
			subprocess
"""


import threading
import datetime
import subprocess
import xml.etree.ElementTree as ET

XMLTree = {}
Newlog = ''
OldLog = ''

def GetXMLTree():
	# store XML file in a Var
	global XMLTree
	filename = 'Mobile Devices in Ipad SRV-chache.xml'
	Tree = ET.parse(filename)
	XMLTree = Tree.getroot()

def replaceOutTerm(string):
	#  replace every embarrassing Char
	str = string.replace("b\'", "")
	str = str.replace("\'", "")
	str = str.replace("]","")
	str = str.replace("\\n", "\n")
	str = str.replace("\\r", "")
	str = str.replace("\\xff", "")
	return str

def GetLog():
	# Execute Log command and store it in Var 
	global Newlog
	global OldLog
	cmd = ["log","show","--predicate","subsystem == 'com.apple.AssetCache'"]
	LogResult = subprocess.run(cmd, capture_output = True, check=True)
	output = subprocess.run(["grep", "equest from"], capture_output = True, input=LogResult.stdout)
	OldLog = Newlog
	Newlog = replaceOutTerm(str(output.stdout))
	return ChangeLog()

def ChangeLog():
	# compare both Log variable 
	LastNewLog = Newlog.split('\n')
	if OldLog != '':
		LastOldLog = OldLog.split('\n')
		if LastNewLog[-2] == LastOldLog[-2]:
			return False
		else:
			return True
	else:
		# Not Sure It works need test, add a delay to prevent from stack overflow 
		datetime.time.sleep(1)
		GetLog()

def viewLog(event):
# Check Log change
	while 1:
		LogChange = GetLog()
		if LogChange == True:
			GetIPFromLog()
		else:
			continue

def GetIPFromLog():
	# Extract IP address from Log
	LastNewLog = Newlog.split('\n')
	temp = LastNewLog[-2].split('equest from')
	temp = temp[-1].split(":")
	IP = temp[0]
	IP = IP.strip()
	IPtoMAC(IP)

def IPtoMAC(IP):
	# scan IP using Nmap command 
	# -sn arg is for ping only not port discovery
	NETGEAR = False
	cmd = ["nmap",IP,"-sn"]
	MACResult = subprocess.run(cmd, capture_output = True, check=True) # execute Nmap command and get output 
	output = subprocess.run(["grep", "MAC Address:"], capture_output = True, input=MACResult.stdout) # execute grep command on the Nmap's output
	output = subprocess.run(["cut", "-c","14-30"], capture_output = True, input=output.stdout) # cut the grep's output to return just the mac address
	MACadrr = replaceOutTerm(str(output.stdout))
	if MACadrr == "":
		cmd = ["arp-scan", IP]
		MACResult = subprocess.run(cmd, capture_output = True, check=True) # execute arp-scan command and get output
		output = subprocess.run(["grep", IP], capture_output = True, input=MACResult.stdout) # execute grep command on the arp-scan's output
		MACadrr = replaceOutTerm(str(output.stdout)) 
		MACadrr = MACadrr.split("\\t")
		if len(MACadrr) > 1:
			# Need to find a way to bypass Netgear switch 
			if MACadrr[-1].strip() == "NETGEAR":
				NETGEAR = True
				MACadrr = MACadrr[1]
				MACadrr = MACadrr.upper()
			else:
				MACadrr = MACadrr[1]
				MACadrr = MACadrr.upper()

	MACadrr = str(MACadrr).strip()
	# Create a Json object
	DeviceInfo = getInfoFromMAC(MACadrr,IP,NETGEAR)
	if DeviceInfo == -1:
		return 1
		# TODO fix MAC addr not found
	else:
		# Write at the end of the file the Json previously created
		f = open("IP_Devices.log", "a+")
		f.write(str(DeviceInfo) + ",\n")
		f.close()

def getInfoFromMAC(MAC,IP,NETGEAR):
	# Return a JSON object
	deviceInfo = []
	InfoStr = ""
	deviceIndex = FindMACInXML(MAC)
	if NETGEAR:
		InfoStr += "{ 'IP' : '" + IP + "' ," # IP Target
		InfoStr += "'Date' : '" + datetime.datetime.now().strftime("%m/%d/%Y-%H:%M:%S") + "'," # Add Log Date
		InfoStr += "'NETGEARMAC' : '" + MAC + "' }" # Store the Netgear Mac address
	elif deviceIndex > -1:
		device += XMLTree[deviceIndex]
		InfoStr += "{ 'IP' : '" + IP + "',"
		InfoStr += "'Date' : '" + datetime.datetime.now().strftime("%m/%d/%Y-%H:%M:%S") + "',"
		# Store every information found in the XML file
		rangeLen =  range(len(device)) 
		for i in rangeLen:
			# check if it's the last one 
			if i == rangeLen - 1:
				InfoStr += "'" + device[i].tag + "' : '" + device[i].text + "' }"
			else
				InfoStr += "'" + device[i].tag + "' : '" + device[i].text + "',"
	else:
		InfoStr += "{ 'IP' : '" + IP + "',"
		InfoStr += "'Date' : '" + datetime.datetime.now().strftime("%m/%d/%Y-%H:%M:%S") + "',"
		InfoStr += "'MAC' : 'NaN'},"

	deviceInfo.append(InfoStr)
	return deviceInfo

def FindMACInXML(MAC):
	# Search in the XML file corresponding MAC address
	DeviceNumber = 0
	sameMAC = False
	# listing all device
	for Devices in XMLTree:
		if sameMAC:
			break
		# listing all the device's informations
		for DeviceInfo in Devices:
			# check only mac address
			if DeviceInfo.tag == "Wi_Fi_MAC_Address":
				if DeviceInfo.text == MAC:
					sameMAC = True
		DeviceNumber = DeviceNumber + 1
	# return only DeviceNumber is realy found not just at the end of the for loop
	if sameMAC:
		return DeviceNumber - 1
	else:
		return -1

GetXMLTree()

ViewLogThread = threading.Thread(target=viewLog, args=(1,))
ViewLogThread.start()

# print("something here")