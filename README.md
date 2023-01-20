# Domain Response

Domain Response is a tool that is designed to help you automate the investigation for a domain. This tool is specificly designed to automated phishing domain investigations. However it can be used for every domain to gather all domain information needed. This can help to classify if a domain is malicious. The script collects the following information in one go. 
- WHOIS
- Certificate
- DNS Records
- Directories

#### WHOIS

WHOIS information is used to determine were and when the site is hosted. For example if a bulletproof hoster is used and the domain is registered 2 days ago this will be shown in the output. This can give a good indication that a domain has or will be used for malicious purposes. 

#### Certificate

All certificates of the site are collected and checked wheter they are recently registered. The output is a list of all certificates for this domain and all subdomains. 

#### DNS Records

The most common DNS records are collected, namely A, AAAA, NS, CNAME, TXT and MX records. With this it can be determined if the site is active and if mails can be send with this domain. That can indicate if a domain is able to send out phishing mails. More records can be added by slightly adjusting the script. 

#### Directory

The Domain Response Tool also checks if a few pages exists on the domain. This is done by sending a request to that specific URL and waiting for the response. It is common that phishers do not use the homepage of a site to host their phishing page. This can check if a /login exists, but also if admin portals exists, which can give an indication if a webserver is running on the domain. The script searches for ['cpanel', 'admin', 'login', 'webadmin', 'wp-admin'] but more can be added. 

# Installation

1. Clone the project
2. Install python dependencies by running:

Windows
```
pip install -r .\requirements.txt
```
Linux
```
pip install -r requirements.txt
```

After the dependencies have been installed the script can be used.

# Usage

The script can be used with different input parameters. 

```
python.exe .\domain_response.py -h
usage: domain_response.py [-h] [-s] [-d DOMAIN]

optional arguments:
  -h, --help            show this help message and exit
  -s, --save            Save Output
  -d DOMAIN, --domain DOMAIN
                        Query domain
```

### Select Target Domain

The -d or --domain can be used to select the domain you want to collect information from. Some examples that can be used to query a domain that all result in output are. Note that the domain will be extracted from any URL you use in the tool. 

```
python.exe .\domain_response.py --domain test.com  
python3.exe .\domain_response.py -d https://test.com
python3.exe .\domain_response.py -d https://test.com/url
```

### Save Output
The output can be saved to a file if the -s or --save parameter is given. This can be used with the same parameters as before for the domain, but with an additional parameter. The file will be saved as 'domainname.com.txt' in your current directory. 
```
python.exe .\domain_response.py -d test.com -s
python.exe .\domain_response.py -s -d test.com
```

### Script Variables
The script contains one variable that is used to determine if a domain certificate has been recently registered. The default value of this variable is 30 days. This can indicate if a domain is used for malicious purposes since recently registered domains are often used for malicious purposes.

```
# Variable to determine when a domain classifies as recent. The default is 30 days.
var_certificate_recently_added = int(30)
```

The output in the script will address that the certificate of the domain has been registered recently by adding the following line to the output. 
```
===== Certificate Information =====
Domain: kqlquery.com Register Date: 2022-12-21 Issuer: C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA
[!] Recently added domain (less than 30 days).
```

## Example output
The domain 

```
python.exe .\domain_response.py -d kqlquery.com
## Banner
Version 1.0
Made by:
Twitter: @BertJanCyber, Github: Bert-JanP


===== TARGET DOMAIN: kqlquery.com =====


===== Whois Information =====

{
  "domain_name": [
    "KQLQUERY.COM",
    "kqlquery.com"
  ],
  "registrar": "NAMECHEAP INC",
  "whois_server": "whois.namecheap.com",
  "referral_url": null,
  "updated_date": [
    "2022-12-21 20:45:22",
    "0001-01-01 00:00:00"
  ],
  "creation_date": "2022-11-24 21:39:06",
  "expiration_date": "2024-11-24 21:39:06",
  "name_servers": [
    "DNS1.REGISTRAR-SERVERS.COM",
    "DNS2.REGISTRAR-SERVERS.COM",
    "dns1.registrar-servers.com",
    "dns2.registrar-servers.com"
  ],
  "status": "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
  "emails": [
    "abuse@namecheap.com",
    "c1aa8b1febf243e69924e93235686a02.protect@withheldforprivacy.com"
  ],
  "dnssec": "unsigned",
  "name": "Redacted for Privacy",
  "org": "Privacy service provided by Withheld for Privacy ehf",
  "address": "Kalkofnsvegur 2",
  "city": "Reykjavik",
  "state": "Capital Region",
  "registrant_postal_code": "101",
  "country": "IS"
}

===== Certificate Information =====

Domain: kqlquery.com Register Date: 2022-12-21 Issuer: C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA
[!] Recently added domain (less than 30 days).
Domain: kqlquery.com Register Date: 2022-12-21 Issuer: C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA
[!] Recently added domain (less than 30 days).

===== DNS Information =====

A Records:
Host 192.64.119.104

AAAA Records:
No Record Found

NS Records:
Host dns2.registrar-servers.com.
Host dns1.registrar-servers.com.

CNAME Records:
No Record Found

TXT Records:
Host "v=spf1 include:spf.efwd.registrar-servers.com ~all"

MX Records:
Host 10 eforward2.registrar-servers.com.
Host 10 eforward3.registrar-servers.com.
Host 15 eforward4.registrar-servers.com.
Host 20 eforward5.registrar-servers.com.
Host 10 eforward1.registrar-servers.com.

===== Directory Information =====

URL: https://kqlquery.com/cpanel HTTP Status Code: <Response [404]>
URL: https://kqlquery.com/admin HTTP Status Code: <Response [404]>
URL: https://kqlquery.com/login HTTP Status Code: <Response [404]>
URL: https://kqlquery.com/webadmin HTTP Status Code: <Response [404]>
URL: https://kqlquery.com/wp-admin HTTP Status Code: <Response [404]>
Error Codes: Informational responses (100 – 199), Successful responses (200 – 299), Redirection messages (300 – 399), Client error responses (400 – 499), Server error responses (500 – 599)
```

## Contributions
Contributions to this script are welcome, this can be done by opening a pull request. If you have a functional addition for the Domain Response Tool but do not want to implement this code yourself, please also open a pull request or send me a message on Twitter to inform me of the idea. 

In case the output of the script will be an error, please open a pull request with the error code. In this way, the script can be improved to fix the issues. 

## Contact

If you have questions or additions feel free to reach out to me on Twitter [@BertJanCyber](https://twitter.com/BertJanCyber)