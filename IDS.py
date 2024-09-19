from scapy.all import *
import datetime

class Rule():
    '''
    Serves to ensure structure and consistency of rules.
    '''
    log_msg = None  # Message to include in log when rule is broken

    protocol = None
    source_ip = None
    source_port = None
    dest_ip = None
    dest_port = None
    content = 'any'
    tcp_flags = 'any'

    filter = False      # Boolean. Indicates if time filter enabled
    filter_secs = None  # Number of seconds
    filter_count = None # Number of packets required in past filter_secs to break rule

    def __init__(self, rule: str):
        '''
        Intitialise an instance of Rule. The string passed to the class
        MUST have the correct form.

        Parameters:
            - rule (str): The string representation of a rule. Must have form:

                alert <protocol> <source-ip> <source-port> -> <dest-ip> <dest-port> (msg: <msg>; content: <content>;)

            Where the data in brackets is optional (brackets must be there regardless)
        '''
        conditions, other = rule.split(' (')
        other = other.split(';')[:-1]
        other = [x.strip(' ') for x in other]

        # Need to pop data outside loop as popping within will skip next element
        msg_index, content_index, flags_index, det_filter_index = None, None, None, None
        for i, s in enumerate(other):
            if s.startswith('msg'):
                msg_index = i
            elif s.startswith('content'):
                content_index = i
            elif s.startswith('flags'):
                flags_index = i
            elif s.startswith('detection_filter'):
                det_filter_index = i
        if msg_index is not None:
            self.log_msg = other[msg_index].split(': ')[1].strip(' \";)\n')
        if content_index is not None:
            self.content = other[content_index].split(': ')[1].strip(' \";)\n')
        if flags_index is not None:
            self.tcp_flags = other[flags_index].split(': ')[1].strip(' \";)\n')
        if det_filter_index is not None:
            self.filter = True
            self.filter_count = int(other[det_filter_index].split(': ')[1].split(', ')[0].split(' ')[1].strip(' \";)\n'))
            self.filter_secs = int(other[det_filter_index].split(': ')[1].split(', ')[1].split(' ')[1].strip(' \";)\n'))
    
        conditions = conditions.split(' ')
        self.protocol = conditions[1]
        self.source_ip = conditions[2]
        self.source_port = conditions[3]
        self.dest_ip = conditions[5]
        self.dest_port = conditions[6]

    def compare(self, trans_prot, net_prot, source_ip, dest_ip, source_port, \
                dest_port, content, tcp_flags):
        '''
        Compare data in the instance of the rule with the parameters passed.

        Parameters:
            As above

        Returns:
            True: If the passed parameters match instance of the rule
            False: Otherwise
        '''
        # Helpful for bug fixes:
        print(f'Supplied:\t{trans_prot}, {source_ip}, {dest_ip}, {source_port}, {dest_port}, {content}, {tcp_flags}')
        print(f'Rule:\t{self.protocol}, {self.source_ip}, {self.dest_ip}, {self.source_port}, {self.dest_port}, {self.content}, {self.tcp_flags}, {self.filter}')

        print(f"{self.protocol == 'any' or self.protocol == trans_prot or self.protocol == net_prot}: self.protocol == 'any' or self.protocol == trans_prot or self.protocol == net_prot")
        print(f"{(self.source_ip == 'any' or self.source_ip == source_ip)}: (self.source_ip == 'any' or self.source_ip == source_ip)")
        print(f"{self.dest_ip == 'any' or self.dest_ip == dest_ip}: self.dest_ip == 'any' or self.dest_ip == dest_ip")
        print(f"{self.source_port == 'any' or self.source_port == source_port}: self.source_port == 'any' or self.source_port == source_port")
        print(f"{self.dest_port == 'any' or self.dest_port == dest_port}: self.dest_port == 'any' or self.dest_port == dest_port")
        print(f"{(self.content == 'any' or (content is not None and self.content in content))}: (self.content == 'any' or (content is not None and content in self.content))")
        print(f"{(self.tcp_flags == 'any' or self.tcp_flags == tcp_flags or ('+' in self.tcp_flags and self.tcp_flags[:-1] in tcp_flags))}: (self.tcp_flags == 'any' or self.tcp_flags == tcp_flags or ('+' in self.tcp_flags and self.tcp_flags[:-1] in tcp_flags))")

        if (self.protocol == 'any' or self.protocol == trans_prot or self.protocol == net_prot) \
            and (self.source_ip == 'any' or self.source_ip == source_ip) \
            and (self.dest_ip == 'any' or self.dest_ip == dest_ip) \
            and (self.source_port == 'any' or self.source_port == source_port) \
            and (self.dest_port == 'any' or self.dest_port == dest_port) \
            and (self.content == 'any' or (content is not None and self.content in content)) \
            and (self.tcp_flags == 'any' or self.tcp_flags == tcp_flags or \
                 ('+' in self.tcp_flags and self.tcp_flags[:-1] in tcp_flags)):
            print('Returning True for rule match')
            return True
        return False

class IDS():
    # A list of Rule() objects containing the attributes of each rule to be
    # check against. Can be populated with the load_rules() method.
    rules = []

    # Path to a file where to write logs for detected intrusions
    logfile_path = None

    # A list of timestamps of recieved TCP packets. This is automatically cleaned up
    # evey time the check_time() method is called, to contain only timestamps within
    # a certain time interval, specified by the filter_secs parameter of the method
    timestamps = []

    def __init__(self, rule_path: str, packets_path: str, log_path: str='IDS_log.txt'):
        '''
        Initialize the Intrusion Detection System. Reads and interprets provided rules,
        and runs system.

        Parameters:
            - rule_path (str): The absolute path the file containing the rule set to be used.
            - packets_path (str): The absolute path to the .pcap file containing the
            packets to be checked.
        '''
        with open(log_path, 'w') as f:
            # Truncate file
            pass
        self.logfile_path = log_path

        self.load_rules(rule_path)
        self.run(packets_path)
    
    def load_rules(self, rule_path: str):
        '''
        Open the file specified in 'rule_path', read each line and create and store a Rule()
        object in self.rules for each rule. Empty lines in the file and lines beginning 
        with # are ignored

        Parameters:
            - rule_path (str): The absolute path the file containing the rules to be loaded
        '''
        with (open(rule_path, 'r') as f):
            lines = f.readlines()

            for line in lines:
                if line == '\n' or line.startswith('#'):
                    continue
                
                self.rules.append(Rule(line.strip('\n')))

    def log(self, msg):
        '''
        Write a log in the logs file (at self.logfile_path) in the format
            
            YYYY-MM-DD HH:MM:SS - Alert: <msg>
        
        Where Y, M, D, H, M, S is the datetime, and msg is the msg passed to function.
        '''
        print('Logging')
        with open(self.logfile_path, 'a+') as f:
            f.write(f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} - Alert: {msg}\n')

    def check_time(self, timestamp, rule, protocol):
        '''
        Determines if there have been greater than filter_count TCP packets recieved (including
        the current one/timestamp) within the last filter_secs seconds. Returns True if there
        have been. otherwise returns False.
        '''
        print('Checking time')
        if protocol != 'tcp' or rule.filter == False:
            return False
        
        # Clean up timestamps
        self.timestamps = [ts for ts in self.timestamps if timestamp - ts < rule.filter_secs]
        
        # Add new timestamp
        self.timestamps.append(timestamp)
        
        print(f'Checking packet at timestamp {timestamp}')
        print(f'Timestamps: {self.timestamps}')

        # Check timestamps
        if len(self.timestamps) > rule.filter_count:
            print(f'Returning True for time match (count: {len(self.timestamps)})')
            return True
        return False
    
    def run(self, packets_path: str):
        '''
        
        '''
        if self.rules == []:
            print("Warning: No rules found. You may want to use load_rules()")

        packets = rdpcap(packets_path)
        for p in packets:
            # Get packet time
            timestamp = p.time

            # String formatting
            p = p.__repr__() # Easier format to work with
            p = p.strip('>')
            p = p.split(' |')[:-1]
            print('-'*20)
            print(p)

            # Get packet info
            net_prot = p[0].split(' ')[0][1:].lower()   # Network protocol (i.e. IP)
            trans_prot = p[1].split(' ')[0][1:].lower() # Transport protocol (udp, icmp, tcp)
            src_ip = p[0].split(' ')[-2].split('=')[1]  # Source IP address
            dest_ip = p[0].split(' ')[-1].split('=')[1] # Destination IP Address

            # Get ports, flags for TCP and UDP packets. ICMP has none
            if trans_prot == 'tcp' or trans_prot == 'udp':
                src_port = p[1].split(' ')[2].split('=')[1]
                dest_port = p[1].split(' ')[3].split('=')[1]
                if trans_prot == 'tcp':
                    tcp_flags = p[1].split(' ')[8].split('=')[1]
                else:
                    tcp_flags = None
            else:
                src_port, dest_port, tcp_flags = None, None, None
            
            # Check if packet contains data
            if len(p) == 3:
                content = p[2].split('=')[1].strip('\'')
            else:
                content = None
            
            # Check for rule matches
            for rule in self.rules:
                if rule.compare(trans_prot, net_prot, src_ip, dest_ip, src_port, dest_port, content, tcp_flags):
                    print('Rule true')
                    if rule.filter is True:
                        print('Has filter')
                        if self.check_time(timestamp, rule, trans_prot):
                            print('filter true')
                            self.log(rule.log_msg)
                        else:
                            continue
                    else:
                        self.log(rule.log_msg)
            