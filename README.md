# intrusion-detection-system
A simple intrusion detection system in python that reads .pcap files and detects packets based on certain rules. Made for the course CYBR3000 at UQ in semester 2, 2024.

To run the program you will need Python v3.9 or later installed, as well as the "Scapy" libary which is used for reading the .pcap files containing the packets to be checked. To run the program enter in the command line from the directory where IDS.py is located: 
'''
<your-python-version> IDS.py <path_to_the_pcap_file> <path_to_the_IDS_rules>
'''
A log file called "IDS_log.txt" will be generated (or truncated if it exists!) in the same directory, containing logs in the form 
'''
YYYY-MM-DD HH:MM:SS - Alert: <msg>
'''
where the timestamp is the system time at the point of logging (not the packet capture time), and "msg" is the message specified in the rule. Each time a rule is matched by a packet, a log is generated in the log file. If a packet is matched by multiple rules, then multiple entries will be in the logfile for that packet. 

Note that since the program is class based, it can also be imported as a module and run from another program. It would also be feasible to relatively easily alter the program to perform real time intrusion detection by making the program read from a file which contains the pcap logs, written by a packet sniffer.