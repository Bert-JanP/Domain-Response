import re
import requests
import whois
from datetime import timedelta, datetime
import dns.resolver
import argparse
import sys
import glob
import os

### Variables ###

# Variable to determine when a domain classifies as recent. Default is 30 days.
var_certificate_recently_added = int(30)
# Script version number
version = 1.1

### Functions ###

# Agument Parser
parser = argparse.ArgumentParser()
parser.add_argument('-s', '--save', action='store_true', help='Save Output')
parser.add_argument('-d', '--domain', dest='domain', type=str, help='Query domain')
parser.add_argument('-sp', '--scan', action='store_true', help='Scan for default pages. This will send request to the suspicious domain and will disclose your IP address.')
parser.parse_args()

def banner():
    banner = '''
8888888b.                                  d8b                           
888  "Y88b                                 Y8P                           
888    888                                                               
888    888  .d88b.  88888b.d88b.   8888b.  888 88888b.                   
888    888 d88""88b 888 "888 "88b     "88b 888 888 "88b                  
888    888 888  888 888  888  888 .d888888 888 888  888                  
888  .d88P Y88..88P 888  888  888 888  888 888 888  888                  
8888888P"   "Y88P"  888  888  888 "Y888888 888 888  888                  
                                                                         
                                                                         
                                                                         
8888888b.                                                                
888   Y88b                                                               
888    888                                                               
888   d88P .d88b.  .d8888b  88888b.   .d88b.  88888b.  .d8888b   .d88b.  
8888888P" d8P  Y8b 88K      888 "88b d88""88b 888 "88b 88K      d8P  Y8b 
888 T88b  88888888 "Y8888b. 888  888 888  888 888  888 "Y8888b. 88888888 
888  T88b Y8b.          X88 888 d88P Y88..88P 888  888      X88 Y8b.     
888   T88b "Y8888   88888P' 88888P"   "Y88P"  888  888  88888P'  "Y8888  
                            888                                          
                            888                                          
                            888  
Version %s                                                            
Developed by: Bert-Jan Pals
Twitter: @BertJanCyber, Github: Bert-JanP
    '''%version
    print(banner)

# Collect the certificate information of the domain that is queried. This also includes subdomains that may have been registered.
def certficate_information(domain):
    print('\n===== Certificate Information =====\n')
    request = requests.get("https://crt.sh/?q=%.{d}&output=json".format(d=domain))
    # Status code that does not equal 200, means that the domain certificate is not available. Which can be the domain does not have a certificate, or is has not been injested into the certificate transparancy logs yet. 
    if request.status_code != 200:
        print('Certificate information not available!')
    for(key, value) in enumerate(request.json()):
        datestring = value['entry_timestamp'].split('T')[0]
        date = datetime.strptime(datestring, '%Y-%m-%d')
        print('Domain: %s Register Date: %s Issuer: %s'%(value['common_name'], datestring, value['issuer_name']))
        minimum_date = (datetime.now()-timedelta(days=var_certificate_recently_added))
        if(date > minimum_date):
            print('\033[91m[!] Recently added domain (less than 30 days).\033[0m')

# Query the whois information of the domain.
def whois_information(domain):
    try:
        print('\n===== Whois Information =====\n')
        info = whois.whois(domain)
        print(info)
    except whois.parser.PywhoisError: 
        print(f'No match for "{domain}"')

# Query DNS data of the domain. It only queries for A, AAAA, NS, TXT, CNAME and MX records. Other can be added see: https://github.com/rthalley/dnspython/blob/master/dns/rdatatype.py#L248
# THe DNS Resolver trows an error if no record exsists, this is catched by the exception in each for loop. 
def dig(domain):
    print('\n===== DNS Information =====\n')
    try:
        try:
            print('A Records:')
            hostA_answers = dns.resolver.resolve(domain)
            for rdata in hostA_answers:
                print('Host', rdata)        
        except dns.resolver.NoAnswer:    
            print('No Record Found')
        try:
            print('\nAAAA Records:')
            hostAAAA_answers = dns.resolver.resolve(domain, 'AAAA')
            for rdata in hostAAAA_answers:
                print('Host', rdata)
        except dns.resolver.NoAnswer:
            print('No Record Found')
        try:        
            print('\nNS Records:')
            hostNS_answers = dns.resolver.resolve(domain, 'NS')
            for rdata in hostNS_answers:
                print('Host', rdata)
        except dns.resolver.NoAnswer:
            print('No Record Found')
        try:   
            print('\nCNAME Records:')     
            hostCNAME_answers = dns.resolver.resolve(domain, 'CNAME')
            for rdata in hostCNAME_answers:
                print('Host', rdata)
        except dns.resolver.NoAnswer:
            print('No Record Found')     
        try:
            print('\nTXT Records:')
            hostTXT_answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in hostTXT_answers:
                print('Host', rdata)
        except dns.resolver.NoAnswer:
            print('No Record Found') 
        try:
            print('\nMX Records:')
            hostMX_answers = dns.resolver.resolve(domain, 'MX')
            for rdata in hostMX_answers:
                print('Host', rdata)                      
        except dns.resolver.NoAnswer:
            print('No Record Found')    
    except dns.resolver.NXDOMAIN:
        print('Domain Does not exsist')
    except dns.resolver.LifetimeTimeout:
        print('DNS Resolver Timeout')    

# Query Default pages on the domain to determine whether the domain is active or under development.          
def default_pages(domain):
    print('\n===== Directory Information =====\n')
    try:
        # List can be appened with custom Control Panels
        directory_list = ['cpanel', 'admin', 'login', 'webadmin', 'wp-admin']
        for dir in directory_list:
            url = f"{'https://'}{domain}{'/'}{dir}"
            response = requests.get(url)
            print("URL: %s HTTP Status Code: %s"%(url, response))
        print('Error Codes: Informational responses (100 – 199), Successful responses (200 – 299), Redirection messages (300 – 399), Client error responses (400 – 499), Server error responses (500 – 599)')
    except:
        print('Errors have ocurred while getting response...')  

# Strip the domain / url to get the valid domain. 
def strip_domain(domain):
    stripped = re.search(r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/?\n]+)", domain)
    if stripped:
        return stripped.group(1)
    print('[!] No Domain could be extracted, try again with a valid domain')
    return 0

# Write to file and print to console depending on settings used. 
class Logger(object):
    def __init__(self):
        self.terminal = sys.stdout
        File = max(glob.iglob('*.txt'), key=os.path.getctime)
        self.log = open(File, "a")
   
    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)  

    def flush(self):
        # this flush method is needed for python 3 compatibility.
        # this handles the flush command by doing nothing.
        # you might want to specify some extra behavior here.
        pass    

def main():
    banner()
    args = parser.parse_args()
    if not args.domain:
        print("\033[91m[!] No domain provided. Please provide a domain with the -d or --domain argument.\033[0m")
        print("\033[91m[!] You can run the script with 'python domain_response.py -h' to get help information.\033[0m")
        return
    if strip_domain(args.domain) != 0:
        target_domain = strip_domain(args.domain)
        if args.save:
            fp = open(f"{target_domain}{'.txt'}", 'w')
            fp.close()
            print('Output save name: %s.txt (Full path: %s)' % (target_domain, os.path.abspath(f"{target_domain}.txt")))
            sys.stdout = Logger()
        print("\n===== TARGET DOMAIN: {d} ===== \n".format(d=target_domain))
        whois_information(target_domain)
        certficate_information(target_domain)
        dig(target_domain)
        # Only run default_pages if --scan is set
        if args.scan:
            default_pages(target_domain)
main()

      
