# Description

For this challenge we were given a fictitious scenario involving a new threat actor called Copper Crow. This actor is operating out of a new area with a focus on ransomeware and extortion. "Our company" has recently noticed an alert for a suspicious phishing email involving this threat actor, and our job is to analyze the malicious document in this email to validate the information and see if there is malware or actions that need our attention.

# Executive Summary

In the excel document "invoice-02-01-2022.xls" provided for this malware investigation we can determine the presence of malicious macros with the use of oletools. The examination of this document in a sandbox gives us information regarding this payload, which was created through a Metasploit framework module. 

Based on the emulation I determined this is a Process Injection - Process Hollowing (T1055.012).  Here the threat actor injects the malicious code into the newly created and suspended rundll32 process in order to evade defenses. A rundll32 process is legitimate and inconspicuous compared to the more common option of executing malicious code as an executable. This makes it hard to differentiate malicious activity from normal operations and from triggering security tools that don't monitor this type of process. The Mitre ATT&CK techniques defines Process Injection - Process Hollowing as a method of executing arbitrary code in the address space of a separate live process, which will be further explained below. Additionally as mentioned in the brief, Copper Crow uses Cobalt Strike which Mitre has listed as a procedure example for Process Injection - Process Hollowing. Cobalt Strike also leverages Metasploit which as previously mentioned was used to create the payload. 

What I suspect is happening is once the document is opened, the AutoOpen() function is triggered which allows the payload to executed a command to open Google Chrome, it then connect to the C2 at shineyobjectd.birds:80 and downloads an executable called metal.exe. This entire process is hidden in the process injection technique. The executable that is downloaded may enable persistence, ultimately creating a backdoor for the attacker through the C2 server. 

# Analysis

1. Initial assessment to verify the type of file and see the file's metadata. I used the file command to verify the file type, and the metadata command to see if there was any important information for this file.

•	command: 

	file invoice-02-01-2022.xls

![file](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/file.png)

•	command: 

	exiftool invoice-02-01-2022.xls

![exiftool](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/exiftool.png)

2. To further analyze this file I used oleid (https://github.com/decalage2/oletools/wiki/oleid). This displays the file properties, such as the presence of malicious macros.

•	command: 

	oleid invoice-02-01-2022.xls

![oleid](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/oleid.png)

3. In order to see the macros on this document I used oledump.py (https://blog.didierstevens.com/programs/oledump-py/), this displayed the streams and macros. There are macros present on stream 8, indicated with the capitalized letter M. I extracted this stream and sent it to a file named "Module1" to analyze. 

•	command: 

	python3 oledump.py invoice-02-01-2022.xls or oledump.py invoice-02-01-2022.xls

- Displayed Stream 8 - Module1 

command: 
	
	oledump.py invoice-02-01-2022.xls -v -s 8 > Module1
	cat Module1
	
![display-stream-8](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/cat-stream-8.png)
	
4. Extracted macros using olevba (https://github.com/decalage2/oletools/wiki/olevba). 

•	command: 

	olevba invoice-02-01-2022.xls 

![olevba](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/olevba.png)
![olevba](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/olevba2.png)

There is an AutoExec in this file, which means that in this phishing campaign, users who received an email with the infected document and who open this document will get infected. 
We can also determine there are some Windows API calls of interest such as CreateThread, VirtualAlloc, RtlMoveMemory, etc., that may inject code into another process. 

5. Using a Python script I converted the array present in the macros into characters and sent the output to strings to analyze. 

•	commands: 

	nano data.py
	
•	enter the following: 
	
	#!/usr/bin/env python3
	
	data = []
	
	print("".join(chr(d)for d in data))

![data.py](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/data-py.png)

note: enter the array inside the brackets. 

run the script: 
	
	python3 data.py
	
6. Displaying the string output I can see that rundll32 process is likely used to appear as normal activity. We can also see the DNS domain and executable used to establish the C2. 

Run the python script, convert the output to strings and send to a file.
	
•	command: 
	
	python3 data.py | strings > dataStrings.py
	
![strings](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/strings.png)
	
7. I used another python script turn the array into a byte array object for further analysis at a later time. 
	
•	commands: 
	
	nano dataTwo.py

•	enter the following: 
	
	#!/usr/bin/env python3
	
	import sys
	
	data = []
	
	sys.stdout.buffer.write(bytearray(data))

note: enter the array inside the brackets. 

![dataEncoded.py](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/data2-py.png)

Run the script and send the output to a file:
	
	python dataTwo.py > dataEncoded

8. For emulation I used speakeasy (https://github.com/mandiant/speakeasy) on the byte array file I created using the python script above.

•	command: 
	
	speakeasy -t dataEncoded -r -a x86 -m -o report.json 
	
![speakeasy](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/speakeasy.png)
	
Displayed .json file generated with speakeasy
	
•	command: 
	
	cat <.json file>

![report](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/display-report.png)
	
## The following are some the findings after the entry point in the emulation:

### Type of entry point: 

shellcode

### Start address: 

0x1000
	
### List of API calls:
	
•	STARTUPINFOA structure (processthreadsapi.h) - " Specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time."  

•	CreateProcessA function (processthreadsapi.h) "Creates a new process and its primary thread."  

•	VirtualAllocEx function (memoryapi.h) - " Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process. The function initializes the memory it allocates to zero."  

•	WriteProcessMemory function (memoryapi.h) - " Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails."  

•	CreateRemoteThread function (processthreadsapi.h) - " Creates a thread that runs in the virtual address space of another process."  

•	Sleep function (synchapi.h) - " Suspends the execution of the current thread until the time-out interval elapses."  

As an example, on line 84 of the of the photo below you can see the CreatProcessA function is called, with the arguments to create a rundll32 process on line 87, then the CREATE_SUSPEND argument on line 91, and the flag to suspend the processes primary thread on line 94, which is indicative of process hollowing. 

![](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/report-2-data-encoded1.png)
![](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/report-2-data-encoded2.png)	
	
### Process events (including event, pid, path, data, etc.):

![process-events](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/process-events.png)
	
In the process events we can see the creation of a process (rundll32), allocation of memory, writing of data (shellcode) into the memory previously allocated and the thread injection taking place. 

9. The following are some online resources I used to further investigate the original file. 
I used tria.ge to analyze the file by uploading it to their samples. This matched the file's hash, which was helpful to do more research on Virus Total and other malware sandbox detection systems. 
Using the sha256 hash I checked to see if there was any information on the file in virus total, particularly the community comments and found some interesting information from inquest labs  
From this comment we can see there is a full report on inquest.labs that gives us more information on the malicious file.  

![tria.ge](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/triage.png)
	
![virus total](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/virus-total.png)
	
![inquest](https://github.com/joaconstrictor/Cyber-Defense/blob/main/Tier-1/images/inquest.png)
	
# IOCs

invoice-02-01-2022.xls	
	
shinyobjects.birds	
	
metal.exe	
	
rundll32	

# Files

File Name: invoice-02-01-2022.xls	

MIME Type: application/vnd.ms-excel	

Size: 24kB 	

SHA256: a3f128976fb477883db4f7ecc2aae05e61e2de224ad584454022aced8f8f5ca5

# References
	
https://attack.mitre.org/techniques/T1055/012/
	
https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
	
https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
	
https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
	
https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
	
https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
	
https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleep
	
https://tria.ge/220415-g7nmhacfb8/behavioral1
  https://www.virustotal.com/gui/file/a3f128976fb477883db4f7ecc2aae05e61e2de224ad584454022aced8f8f5ca5/details

https://labs.inquest.net/dfi/sha256/a3f128976fb477883db4f7ecc2aae05e61e2de224ad584454022aced8f8f5ca5

