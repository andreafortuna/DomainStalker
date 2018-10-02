#!/usr/bin/env python3

# By Andrea Fortuna - andrea@andreafortuna.org - https://www.andreafortuna.org

import argparse
from os import path
import dns.resolver
from re import compile
from time import sleep
from requests import get
from random import choice
from bs4 import BeautifulSoup
from datetime import datetime
from sys import exit, argv, stdout
from threading import Thread, activeCount
from urllib3 import disable_warnings, exceptions
disable_warnings(exceptions.InsecureRequestWarning)

USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0.2 Safari/604.4.7","Mozilla/5.0 (X11; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0","Mozilla/5.0 (iPad; CPU OS 11_2_1 like Mac OS X) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0 Mobile/15C153 Safari/604.1","Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0;  Trident/5.0)"]

FOUND = {}

def dns_lookup(target, lookup_type):
    results = []
    try:
        res = dns.resolver.Resolver()
        res.timeout = 2
        res.lifetime = 2
        dns_query = res.query(target, lookup_type)
        dns_query.nameservers = ['8.8.8.8', '8.8.4.4']
        for name in dns_query:
            results.append(str(name))
    except:
        pass
    return results

def get_request(link, timeout):
    head = {
        'User-Agent': '{}'.format(choice(USER_AGENTS)),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'}
    return get(link, headers=head, verify=False, timeout=timeout)

def search_thread(source, target):
    for link in SiteSearch().search(source, target, 20):
        try:
            sub = link.split("/")[2].strip().lower()
            if target in sub and sub not in FOUND and sub.count('.') > 1:
                subdomain_output(sub, source)
        except:
            pass

class SiteSearch():
    URL = {'google': 'https://www.google.com/search?q=site:{}&num=100&start={}',
           'bing': 'http://www.bing.com/search?q=site:{}&first={}',
           'yahoo': 'https://search.yahoo.com/search?p=site:{}&b={}' 
           }

    def __init__(self):
        self.links = []  
        self.running = True

    def timer(self, time):
        sleep(time)
        self.running = False

    def search(self, search_engine, site, timeout):
        self.running = True     
        Thread(target=self.timer, args=(timeout,), daemon=True).start() 
        self.search_links = 0   
        self.site_links = 0     
        found_links = 0       

        while self.running:
            if self.search_links > 0 and found_links == self.site_links:
                return self.links
            found_links = self.site_links
            try:
                self.site_search(search_engine, self.search_links, site)
            except Exception as e:
                pass
        return self.links

    def site_search(self, search_engine, count, site):
        HTTP = compile("http([^\)]+){}([^\)]+)".format(site))
        HTTPS = compile("https([^\)]+){}([^\)]+)".format(site))
        #print ("DEBUG:" + self.URL[search_engine].format(site, count))
        for link in get_links(get_request(self.URL[search_engine].format(site, count), 3)):
            #print ("DEBUG:" + link)
            if search_engine not in link.lower():
                self.search_links += 1
                if HTTP.match(link) or HTTPS.match(link):
                    self.site_links += 1
                    if link not in self.links:
                        self.links.append(link)

def get_links(raw_response):
    links = []
    soup = BeautifulSoup(raw_response.content, 'html.parser')
    for link in soup.findAll('a'):
        try:
            links.append(str(link.get('href')))
        except:
            pass
    return links

def virustotal_thread(target):
    count = 0
    try:
        resp = get_request("https://www.virustotal.com/en/domain/{}/information/".format(target), 5)
        data = resp.content.decode('utf-8').splitlines()
        for line in data:
            count += 1
            if '<div class="enum ">' in line:
                sub = extract_sub(target, data[count])
                if sub not in FOUND and sub.count('.') > 1:
                    subdomain_output(sub, "Virus-Total")
    except:
        pass

def extract_sub(target, html):
    try:
        if target in html:
            return html.split("/en/domain/")[1].split("/information")[0]
    except:
        return False


def sub_respcode(sub):
    results = []
    try:
        results.append(get_request("http://"+sub, 2).status_code)
    except:
        results.append("Err")

    try:
        results.append(get_request("https://"+sub, 2).status_code)
    except:
        results.append("Err")
    return results

def subdomain_output(sub, source):
    http = sub_respcode(sub)
    dns = dns_lookup(sub, 'A')
    FOUND[sub] = dns, http
    stdout.write("\033[1;34m{:<13}\033[1;m\t{:<25}\t({:<3}/{:<3})\t{}\n".format('{}'.format(source), sub, http[0], http[1], dns))

def main(args):
    try:
        stdout.write("\n\033[1;30m{:<13}\t{:<25}\t({:<9})\t{}\033[1;m\n".format('Source', 'Subdomain', 'http/https', 'IP Resolution'))
        Thread(target=virustotal_thread, args=(args.target,), daemon=True).start()
        Thread(target=search_thread, args=('yahoo', args.target,), daemon=True).start()
        Thread(target=search_thread, args=('bing', args.target,), daemon=True).start()
        Thread(target=search_thread, args=('google', args.target,), daemon=True).start()
        while activeCount() > 1:
            sleep(0.001)

        if not FOUND:
            return

    except KeyboardInterrupt:
        exit(0)
    except Exception as e:
        stdout.write("\033[1;30m{:<13}\t{:<25}\033[1;m\n".format('[Error-01]', str(e)))

if __name__ == '__main__':
    version = "1.1.0"
    print("""
  ____                        _       
 |  _ \  ___  _ __ ___   __ _(_)_ __  
 | | | |/ _ \| '_ ` _ \ / _` | | '_ \ 
 | |_| | (_) | | | | | | (_| | | | | |
 |____/ \___/|_| |_| |_|\__,_|_|_| |_|
  ____  _        _ _                  
 / ___|| |_ __ _| | | _____ _ __      
 \___ \| __/ _` | | |/ / _ \ '__|     
  ___) | || (_| | |   <  __/ |        
 |____/ \__\__,_|_|_|\_\___|_|        
                                   v0.1
Andrea Fortuna - andrea@andreafortuna.org - https://www.andreafortuna.org
""")


    args = argparse.ArgumentParser(description="""
Script to perform subdomain enumeration using google, bing, yahoo and virusTotal.com, 
providing record resolution and http/https response codes. 

usage:
    python3 {0} target""".format(argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)

    args.add_argument(dest='target', nargs='+', help='Target domain')
    args = args.parse_args()
    args.target = args.target[0]
    main(args)
