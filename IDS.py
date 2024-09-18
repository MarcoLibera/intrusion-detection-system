from scapy.all import *

class Rule():
    '''
    Serves to ensure structure and consistency of rules.
    '''
    protocol = None
    source_ip = None
    source_port = None
    dest_ip = None
    dest_port = None
    msg = None
    others = None

    def __init__(self, rule: str):
        '''
        Intitialise an instance of Rule. The string passed to the class
        MUST have the correct form.

        Parameters:
            - rule (str): The string representation of a rule. Must have form:

                alert <protocol> <source-ip> <source-port> -> <dest-ip> <dest-port> (msg: <msg>; <other>)

            Where <other> can be zero or more other conditions to check. Each condition is separated
            by a semicolon (;). Stored as a list of conditions
        '''
        conditions, other = rule.split(' (')

        other = other[:-2] # Remove trailing semicolon and closing bracket
        other = other.split('; ')
        for i, s in enumerate(other):
            if s.startswith('msg'):
                self.msg = other.pop(i).split(': ')[1].strip('\"')
        self.others = other
    
        conditions = conditions.split(' ')
        self.protocol = conditions[1]
        self.source_ip = conditions[2]
        self.source_port = conditions[3]
        self.dest_ip = conditions[5]
        self.dest_port = conditions[6]


class IDS():
    # A list of Rule() objects containing the attributes of each rule to be
    # check against. Can be populated with the load_rules() method.
    rules = []

    def __init__(self, rule_path: str = None, packets_path: str = None):
        '''
        Initialize the Intrusion Detection System. Reads and interprets provided rules,
        and runs system.

        Parameters:
            - rule_path (str): The absolute path the file containing the rule set to be used.
            - packets_path (str): The absolute path to the .pcap file containing the
            packets to be checked.
        '''
        if rule_path is not None:
            self.load_rules(rule_path)
        
        if packets_path is not None:
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
                
                self.rules.append(Rule(line))
    
    def run(self, packets_path):
        '''
        Checks the 
        '''
        packets = rdpcap(packets_path)
        print(packets)