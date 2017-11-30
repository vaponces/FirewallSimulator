import os
import sys
import string


#Dictionary that keeps track of incoming and outgoing rules
incomingRules={}
outgoingRules={}

# This function akes the input filename and processes the rules into two different
# dictionaries. Incoming and Outgoing rules. If there is an invalid line it prints
# an error statement, the line number, and it proceeds with the following rule.
def setRules(filename):
    global incomingRules
    global outgoingRules
    lineNumber=1
    # Try to open file and process a line
    try:
        file=open(filename, 'r')
        for line in file:
            line=line.strip().lower()
            words=line.split()
            for word in words:
                word=word.strip()
            # Empty lines are ignored
            if(len(words)==0):
                pass
            elif(words[0]=='in'):
                incomingRules[lineNumber]= words
            elif (words[0]=='out'):
                outgoingRules[lineNumber]= words
            # Lines that start with # are ignored
            elif(words[0].startswith('#')):
                pass
            # Invalid lines print error statement
            else:
                print('Error! Line '+str(lineNumber)+' is invalid.')
                pass
            lineNumber+=1
        file.close()
    except:
        print('Error: This file cannot be processed')

# This function turns the ip address in the rules to a binary number for easier
# comparison. It changes it in the dictionaries, incoming and outgoing rules.
def ipToBinary(rules):
    for rule in rules:
        ip=rules[rule][2]
        if(ip=='*'):
            continue
        else:
            # Try to convert to binary if not an error is printed.
            try:
                intIP = map(int, ip.split('/')[0].split('.'))
                toBinary = '{0:08b}{1:08b}{2:08b}{3:08b}'.format(*intIP)
                range = int(ip.split('/')[1]) if '/' in ip else None
                if range==None:
                    rules[rule][2]=toBinary
                else:
                    rules[rule][2]=toBinary[:range]
            except:
                print('Sorry but it appears and invalid IP has been entered in line '+str(rule))

# This function turns the ip address in the packets to a binary number for easier
# comparison. It also takes / into account if present in a packet.
def intToBinary(ip):
    intIP = map(int, ip.split('/')[0].split('.'))
    toBinary = '{0:08b}{1:08b}{2:08b}{3:08b}'.format(*intIP)
    range = int(ip.split('/')[1]) if '/' in ip else None
    if range==None:
        return toBinary[:range]
    else:
        return toBinary


# This functions checks if a packet is in correct format. If correct it returns True, else
# it return False.
def checkPacket(packet):
    # Packets must have four variables in length
    if (len(packet)!= 4):
        print('Sorry but this packet line has an incorrect number of arguments. Proceeding..')
        return False
    # Packet can only have in or out as a direction.
    if(packet[0]!='in'):
        if(packet[0]!='out'):
            print('Sorry but this packet has an invalid direction')
            return False
    # Checks for a valid ip address in the packet
    try:
            ip=intToBinary(packet[1])
    except:
        print('Error, this packet line contains an invalid ip address. Proceeding...')
        return False
    # Checks for a valid port in the packet
    try:
        if ((int(packet[2])<0) or (int(packet[2])>65535)):
            print('Sorry this packet line contains an invalid port. \n Valid ports are between 0 and 65535. Proceeding...')
            return False
    except ValueError:
        print('Sorry this packet line contains an invalid port. Proceeding...')
        return False
    return True

# This function handles one packet at a time an compares it to the rules previously set.
# Checks for a port match, ip match and for established rues.
def handleAuthorization(packet):

    #Obtain port and ip from packet  
    packetPort=packet[2]
    packetPort=packetPort.strip()  
    packetIP=intToBinary(packet[1])

    #Check for incoming packets in incomingRules
    if(packet[0]=='in'):
        drop=True
        for rule in incomingRules:
            portMatch=False
            ipMatch=False
            established=False

            #Check if rule was established
            if('established' in incomingRules[rule]):
                established=False
            else:
                established=True
            
            if not established:
                if (incomingRules[rule][4]=='established' and packet[3]=='1'):
                    established=True
                    

            #Check for IP Match
            if(incomingRules[rule][2]=='*'):
                ipMatch=True

            if(incomingRules[rule][2] in packetIP[:len(incomingRules[rule][2])]):
               ipMatch=True

            #Check for Port Match
            if(',' in incomingRules[rule][3]):
                portList=incomingRules[rule][3].split(',')
                for port in portList:
                    if (port==packetPort):
                        portMatch=True
            if(incomingRules[rule][3]=='*'):
                portMatch=True
            if(packetPort==incomingRules[rule][3]):
                portMatch=True

            #If all are a match print the corresponding rule and the corresponding packet
            if ipMatch and portMatch and established:
                print('%s(%s) %s %s %s %s '  %   (incomingRules[rule][1],rule,'in',packet[1],packetPort,packet[3]) )
                drop=False
                break
        # If the rule wasnt handled then it is dropped
        if (drop==True):
            print('%s() %s %s %s %s'  %   ('drop','in',packet[1],packet[2],packet[3]) )

    # Check for outgoing packets in outgoing rules
    elif(packet[0]=='out'):
        drop=True
        for rule in outgoingRules:
            portMatch=False
            ipMatch=False

            #Check if rule was established
            if('established' in outgoingRules[rule]):
                established=False
            else:
                established=True

            if not established:
                if (outgoingRules[rule][4]=='established' and packet[3]=='1'):
                    established=True
                    
            #Check for IP Match
            if(outgoingRules[rule][2]=='*'):
                ipMatch=True

            if(outgoingRules[rule][2] in packetIP[:len(outgoingRules[rule][2] )]):
                ipMatch=True 
            #Check for Port Match
            if(',' in outgoingRules[rule][3]):
                portList=outgoingRules[rule][3].split(',')
                if(packetPort in portList):
                    portMatch=True
            if(outgoingRules[rule][3]=='*'):
                portMatch=True
            if(packetPort==outgoingRules[rule][3]):
                portMatch=True

           #If all are a match print the corresponding rule and the corresponding packet
            if ipMatch and portMatch and established:
                print('%s(%s) %s %s %s '  %   (outgoingRules[rule][1],rule,'out',packet[1],packetPort) )
                drop=False
                break
        # If the rule wasnt handled then it is dropped
        if (drop==True):
            print('%s() %s %s %s %s'  %   ('drop','out',packet[1],packet[2],packet[3]) )


# Main Function
filename=None
# Obtain filename from arguments
if(len(sys.argv)>=2):
    filename=sys.argv[1]
else:
    print('Sorry you have entered an incorrect number of arguments.\n  The correct format is python3 fw.py filename')

#Check if file exists and if it is a file
if not os.path.exists(filename):
    print('Sorry this file does not exist.')
    sys.exit(1)
if not os.path.isfile(filename):
    print('Sorry this is an invalid file')
    sys.exit(1)

# Call other functions to set rules and change ip addresses to binary
setRules(filename)
ipToBinary(incomingRules)
ipToBinary(outgoingRules)

# Try to read packet.
try:
    for line in sys.stdin:
        line = line.strip().lower()
        if (line != ""):
            packet = line.split()
            # If packet is valid then handle the packet.
            if(checkPacket(packet)==True):
                handleAuthorization(packet)

except:
    print('Sorry, this packet file cannot be processed.')
