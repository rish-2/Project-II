from scapy.all import *
from scapy.layers.inet import TCP,IP,UDP,ICMP
from scapy.layers.http import HTTPRequest
from scapy.interfaces import ifaces
import socket
import datetime
import os
import time
from colorama import Fore,Back,init
from termcolor import colored

init()                           
#initialising colorama 
#from geoip import geolite2
#hstname=socket.gethostname()
#ipadd=socket.gethostbyname(hstname)
cg=Fore.GREEN
cb=Fore.BLUE
cr=Fore.RED
cm=Fore.LIGHTMAGENTA_EX
res=Fore.RESET

ipadd='192.168. .'             #<===!!!!!!!CHANGE IP BEFORE EXECUTING!!!!!!!!===>
interface = IFACES.dev_from_index(<number>)  #<===!!!!!!!CHECK INTERFACE USING SCAPY IN CMD AND IFACES!!!!!!!!===>
def packet_TCP(pckt):
    print('\u21c5'+ str(" [{}] ".format(time.strftime("%H:%M:%S")))+"   "+"TCP-IN:{}".format(str(len(pckt[TCP]))+"Bytes"+"\n"
    +"SRC-MAC:"+ str(pckt.src)+"    "+"DST-MAC:"+str(pckt.dst)+
    "\n"+"SRC-PORT:"+ str(pckt[TCP].sport)+"    "+"DST-PORT:"+str(pckt[TCP].dport)+"\n"))
def packet_UDP(pckt):
    print('\u21c5'+str(" [{}] ".format(time.strftime("%H:%M:%S")))+"    "+"UDP-OUT:{}".format(str(len(pckt[UDP]))+"Bytes"+"\n"
    +"SRC-MAC:"+str(pckt.src)+"    "+"DST-MAC:"+str(pckt.dst)+
    "\n"+"SRC-PORT:"+str(pckt[UDP].sport)+"    "+"DST-PORT:"+str(pckt[UDP].dport)+"\n"+"SRC-IP:"+str(pckt.src)+"    "+"DST-IP:"+str(pckt.dst)))
def packet_ICMP(pckt):
    print('\u21c5'+str(" [{}] ".format(time.strftime("%H:%M:%S")))+"    "+"ICMP-OUT:{}".format(str(len(pckt[ICMP]))+"Bytes"+"  "
    +"IP-VERSION: "+str(pckt[IP].version)+"\n"+"SRC-MAC:"+str(pckt.src)+"    "+"DST-MAC:"+str(pckt.dst)+
    "\n"+"SRC-PORT:--"+"   "+"DST-PORT:--"+"\n"+"SRC-IP:"+str(pckt[IP].src)+"    "+"DST-IP:"+str(pckt[IP].dst)))
def Packet_Monitor(pckt):
    tme=datetime.datetime.now()
    #hstname=socket.gethostname()
    #ipadd=socket.gethostbyname(hstname)
    #print(hstname+" : "+ipadd)
    if TCP in pckt:
        if IP in pckt:
        #print(pckt[IP].dst)
        #packet_TCP(pckt)
            if ipadd==pckt[IP].src:
                print(f"{cb}\u2191"*25+f"{cm}TCP-OUT{res}"+f'{cb}\u2191'*25)
                print(str(" [{}] ".format(time.strftime("%H:%M:%S")))+"\nSIZE:{}{}".format(str(len(pckt[TCP]))+" Bytes"+"\n"
                +"SRC-MAC:"+ str(pckt.src).ljust(20)+"DST-MAC:"+str(pckt.dst)+
                "\n"+"SRC-PORT:"+ str(pckt[TCP].sport).ljust(19)+"DST-PORT:"+str(pckt[TCP].dport)+"\n"+"SRC-IP:"+str(pckt[IP].src).ljust(17)+"    "+"DST-IP:"+str(pckt[IP].dst),res))
            if ipadd==pckt[IP].dst:
                print(f"{cg}\u2193"*25+f"{cm}TCP-IN{res}"+f"{cg}\u2193"*25)
                print(str(" [{}] ".format(time.strftime("%H:%M:%S")))+"\nSIZE:{}{}".format(str(len(pckt[TCP]))+" Bytes"+"\n"
                +"SRC-MAC:"+ str(pckt.src).ljust(20)+"DST-MAC:"+str(pckt.dst)+
                "\n"+"SRC-PORT:"+ str(pckt[TCP].sport).ljust(19)+"DST-PORT:"+str(pckt[TCP].dport)+"\n"+"SRC-IP:"+str(pckt[IP].src).ljust(21)+"DST-IP:"+str(pckt[IP].dst),res))
    if HTTPRequest in pckt:
        # if this pckt is an HTTP Request
        # get the requested URL
        ip=ipadd
        url = pckt[HTTPRequest].Host.decode() + pckt[HTTPRequest].Path.decode()
        # get the requester's IP Address
        if IP in pckt:
            ip = pckt[IP].src
        # get the request method
    
        method = pckt[HTTPRequest].Method.decode()
        print(f"\n{cm}[+]{cr}{ip}{res}{cm} Requested {url} with {method} at {tme}{res}")
        if  Raw in pckt and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print(f"\n{cr}[*] Some useful Raw data: {pckt[Raw].load}{res}")
    if pckt.haslayer(UDP):
        #packet_UDP(pckt)
        if IP in pckt:
            if ipadd==pckt[IP].dst:
                print(f"{cg}\u2193"*25+f"{cm}UDP-IN{res}"+f'{cg}\u2193'*25)                            
                print(str(" [{}] ".format(time.strftime("%H:%M:%S")))+" "+"\nSIZE:{}".format(str(len(pckt[UDP]))+"Bytes"
                +"\nSRC-MAC:"+str(pckt.src).ljust(20)+"    "+"DST-MAC:"+str(pckt.src)+
                "\n"+"SRC-PORT:"+str(pckt.sport).ljust(19)+"    "+"DST-PORT:"+str(pckt.dport)+"\n"+
                "SRC-IP:"+str(pckt[IP].src).ljust(17)+"    "+"DST-IP:"+str(pckt[IP].dst),res))
            if ipadd==pckt[IP].src:
                print(f"{cb}\u2191"*25+f"{cm}UDP-OUT{res}"+f"{cb}\u2191"*25)                            
                print(str(" [{}] ".format(time.strftime("%H:%M:%S")))+" "+"\nSIZE:{}".format(str(len(pckt[UDP]))+"Bytes"+"\n"
                +"SRC-MAC:"+str(pckt.src).ljust(20)+"    "+"DST-MAC:"+str(pckt.src)+
                "\n"+"SRC-PORT:"+str(pckt.sport).ljust(19)+"    "+"DST-PORT:"+str(pckt.dport)+"\n"+
                "SRC-IP:"+str(pckt[IP].src).ljust(17)+"    "+"DST-IP:"+str(pckt[IP].dst),res))
    if pckt.haslayer(ICMP):
        
        #packet_ICMP(pckt)
        if IP in pckt:
            if ipadd==pckt[IP].dst:
                print(f"{cg}\u2193"*25+f"{cm}ICMP-IN{res}"+f'{cg}\u2193'*25)                         
                print(str(" [{}] ".format(time.strftime("%H:%M:%S")))+" "+"\nSIZE:{}".format(str(len(pckt[ICMP]))+"Bytes"+"\n"
                +"IP-VERSION:IPv"+str(pckt[IP].version)+"\n"+"SRC-MAC:"+str(pckt.src).ljust(20)+"    "+"DST-MAC:"+str(pckt.dst)+
                "\n"+"SRC-PORT:"+str(pckt.sport).ljust(19)+"    "+"DST-PORT:"+str(pckt.dport)+"\n"+
                "SRC-IP:"+str(pckt[IP].src).ljust(17)+"    "+"DST-IP:"+str(pckt[IP].dst),res))
            if ipadd==pckt[IP].src:
                print(f"{cb}\u2191"*25+f"{cm}ICMP-OUT{res}"+f"{cb}\u2191"*25)                            
                print(str(" [{}] ".format(time.strftime("%H:%M:%S")))+" "+"\nSIZE:{}".format(str(len(pckt[ICMP]))+"Bytes"+"\n"
                +"IP-VERSION:IPv"+str(pckt[IP].version)+"\n"+"SRC-MAC:"+str(pckt.src).ljust(20)+"    "+"DST-MAC:"+str(pckt.dst)+
                "\n"+"SRC-PORT:"+str(pckt.sport).ljust(19)+"    "+"DST-PORT:"+str(pckt.dport)+"\n"+
                "SRC-IP:"+str(pckt[IP].src).ljust(17)+"    "+"DST-IP:"+str(pckt[IP].dst),res))         


if __name__=='__main__':
    sniff(prn=Packet_Monitor,iface=interface)   #to capture http add filter="port 80"
