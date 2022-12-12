The tool is made specially for packet capturing in windows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Requirements
*Python must be installed in the system.
*Install required modules from requirements.txt using following command
	pip install -r requirements.txt
*System must have a internet connection.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Setting up the Environment <Windows>:

1.Install a tool npcap which is a Windows Packet Capture Library. (https://npcap.com/dist/npcap-1.71.exe)

2.Search for services in taskbar and open it.Enable the "Routing and Remote access" option.

![image](https://user-images.githubusercontent.com/98183318/207122289-7213964d-8b52-4cc0-9449-244a65596d33.png)

 
3.To enable IP forwarding.Open Command Prompt as administrator, copy the command below and hit enter.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /t REG_DWORD /v IPEnableRouter /d 1 /f
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
![image](https://user-images.githubusercontent.com/98183318/207124464-42bd8122-6779-4e44-bc20-e5f54419dc46.png)

  
4.Run the spoofer.py as administrator. [spoofer.py [-h] [-v] (target) (host or gateway)] 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
For instance, if you want to spoof 192.168.11.7 and the gateway is 192.168.11.1: 
python spoofer.py 192.168.11.7 192.168.11.1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

5.Update IP address of your system in sniffer.py. 
>Type *ipconfig* in Command Prompt to check ip address.

![image](https://user-images.githubusercontent.com/98183318/207125999-2984c3a5-f505-45f2-bd0f-3c3b5c4dd382.png)

6.Update Interface index in sniffer.py. **Type _scapy_ in Command Prompt and then type _ifaces_. Check the index no. which matches your IP.**

![image](https://user-images.githubusercontent.com/98183318/207127415-fa101197-d050-445d-880f-0669112afa40.png)

7.Then Run sniffer.py and capture HTTP,TCP,UDP traffic live.

Happy Hacking :)
