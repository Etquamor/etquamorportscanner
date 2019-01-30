__author__ = "Etquamor"
__date__ = "31.01.2019"

import socket
import sys
import time
import sqlite3
import os
import argparse

# Check parameters
def parameterChecker():
    global ports

    parser = argparse.ArgumentParser()
    parser.add_argument("--target","-t", help="This parameter will define your target.", required=True, type=str)
    parser.add_argument("--wellknownports","-wkp", help="This parameter will scan well known ports.",required=False, action='store_true')
    parser.add_argument("--selectportrange","-spr", help="You need enter port range like : -spr 50-250",required=False)
    parser.add_argument("--port","-p", help="This parameter will scan all entered ports" ,nargs="+",required=False, type=int)
    parser.add_argument("--portlist","-pl", help="This parameter will scan entered ports in port list" ,required=False, type=str)
    arguments = parser.parse_args()

    if arguments.wellknownports:
        setPort = portEditor(arguments.wellknownports, WellknownPorts = True)
        
    elif arguments.selectportrange:
        setPort = portEditor(arguments.selectportrange, SelectPortrange = True)

    elif arguments.port:
        setPort = portEditor(arguments.port, Port = True)

    elif arguments.portlist:
        setPort = portEditor(arguments.portlist, Portlist = True)
        
    else:
        setPort = portEditor(None, WellknownPorts = True)

    scanPort(arguments.target, setPort)

def portEditor(portParameter, WellknownPorts = None, SelectPortrange = None, Port = None, Portlist = None):
    if WellknownPorts == True:
        ports = range(0,1024)                           # Range 0-1024 is well-known ports range
        otherWellKnownPorts = [5555, 3306, 6697, 3389]  # Other well-known ports
        ports = list(ports)+otherWellKnownPorts         # Merge first 1024 port and other well-known ports
        
    elif SelectPortrange == True:
        ports = range(int(portParameter.split("-")[0]), int(portParameter.split("-")[1])+1)
        
    elif Port == True:
        ports = portParameter
        
    elif Portlist == True:
        ports = []                                     # We create list for add port in port list in future
        with open(portParameter,"r") as portListFile:  # Open port list file
            for port in portListFile.readlines():      # Read ports line by line
                try:                                   # Check if your list be formed of integers
                    ports.append(int(port.strip()))    # Add ports list ports in ports list file
                except ValueError:
                    print("\nPlease check if your list be formed of integers.\n")
    return ports

# This function will try connect ports and 
# add connected ports on list for print in future 
def scanPort(host,ports):
    openPorts = []           # openPorts list for add connectable ports
    startTime = time.time()  # startTime variable for calculate scan time in future
    print("\n[*] Scanning...\n")    
    for port in ports:       # Select port one by one in ports
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create socket
            s.settimeout(0.2)
            s.connect((host, port))  # Try connect port  -------------------------------------------\
            openPorts.append(port)   # If connection is succesful add port to list -----------------|
            print("[+] Finded Open Port! :",port) # Print found open ports at the same time         |
            s.close() # Close socket for next port connection try                                   |
        except ConnectionRefusedError: # except ConnectionRefusedError for if socket unsuccesful <=-/
            continue    # If socket connection is unsuccesful try again.
        except KeyboardInterrupt:                           # \
            print("\n[-] Pressed Ctrl+C\n\nQuitting...")    #  \--===> If user press Ctrl+C 
            time.sleep(1)                                   #  /--===> exit program
        except OSError:           # If there is no router for host continue
            continue
        except OverflowError:
            print("\n[-] port must be in range 0-65535.\n")
    # Calculate total scan time second type
    totalTime = str(time.time()-startTime).split(".", 1)[0]+"."+str(time.time()-startTime).split(".", 1)[1][0:3]
    printPort(host, openPorts, totalTime)

# found open ports printer function
def printPort(host, openPortList, scanTime):
    database = sqlite3.connect(databasePath) # Connect port database
    databaseCursor = database.cursor()     # Create database cursor for execute operations
    if len(openPortList) == 0:    # If there is not open ports stop process
        print(host,"dont have any open port.\n\n")
        return False
    try:
        for open_port in openPortList:  # select open ports in open port list
            # Select port informations in database
            databaseCursor.execute("SELECT tcp_udp, nameOfService, descriptionOfService FROM etquamorportscanner WHERE port = ?",(str(open_port),))
            portAttributes = databaseCursor.fetchall()
            protocols = []     # Protocols list for port protocols
            for i in range(0,len(portAttributes)):
                try:
                    protocols.append(portAttributes[i][0]) # Add selected port protocols in protocols list
                except IndexError:
                    protocols.append("None")  # If there is no protocol for selected port add none to protocol list
            try:
                service = portAttributes[0][1] # Add selected port's service
            except IndexError:
                service = "None" # If there is no defined service for selected port define service to "None"
            try:
                description = portAttributes[0][2] # Add selected port's service description
            except IndexError:
                description = "None" # If there is no defined description for selected port define description to "None"

            for protocol in protocols:
                if protocols.count(protocol) > 1:
                    for i in range(protocols.count(protocol)-1):
                        protocols.remove(protocol)
            protocols = "/".join(protocols)

            print((43*"=")+"\nPort:",open_port)
            print("Protocol:",protocols)
            print("Service:",service)
            print("Description:",description)                    

        #Print total time and close database
        print((45*"=")+"\n\t Scaned in :",scanTime,"seconds.\n\n")
        database.close()
        
    except sqlite3.OperationalError:
        database.close()
        if EtquamorPSDatabaseCreator.askForCreateDatabase():
            scanPort(host, openPortList, scanTime)
        

if __name__=="__main__":
    try:
        from PortScannerDatabase import EtquamorPSDatabaseCreator
        databasePath = "PortScannerDatabase/EtquamorPSDatabase.db"
        parameterChecker()
    except Exception as e:
        print("[-] Unexpected Error!\n[#] Error ==>",e)
else:
    databasePath = "EtquamorHackTools/PortScannerDatabase/EtquamorPSDatabase.db"