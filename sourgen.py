#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
File for generation files for feak feed
"""

import os
from optparse import OptionParser
from random import randint
from random import choice
from string import letters

parser = OptionParser()
parser.add_option("-4", "--ip4", default=0, metavar="NNN",
                  action="store", type="int", dest="ip4_cnt",
                  help="generate fake feeds file that will contain NNN"\
                  " IPv4 addresses")
parser.add_option("-6", "--ip6", default=0, metavar="NNN",
                  action="store", type="int", dest="ip6_cnt",
                  help="generate fake feeds file that will contain NNN"\
                  " IPv6 addresses")
parser.add_option("-g", "--grey", default=False,
                  action="store_true", dest="ip_type",
                  help="take into files only 'grey' IP addresses"\
                  " (e.g: 192.168.0.0/24)")
parser.add_option("-D", "--domain", default=0, metavar="DDD",
                  action="store", type="int", dest="dom_cnt",
                  help="generate fake feeds file that will contain DDD"\
                  " domain names")
parser.add_option("-s", "--separate",
                  action="store_true", dest="separate", default=False,
                  help="store each fake feeds file as a separate file")
parser.add_option("-d", "--debug",
                  action="store_true", dest="debug", default=False,
                  help="print status information in stdout."\
                  " Under construction")
parser.add_option("-f", "--file", metavar="FILE", default="feed",
                  action="store", type="string", dest="filename",
                  help="the name of fake feed file. In case when we use --separate options"\
                  " there will be created several files with this NAME and additional extension"\
                  " (i.e: FILE.ip4, FILE.ip6, FILE.dom)")
(options, args) = parser.parse_args()

### =============================================================
def generate_ip4(cnt, flg):

    """ 
    cnt (int)  - quantity of ip4 addresses
    flg (bool) - flag that shows or include in file real (true) or grey (false) IP addresses
    """
    ip4_list = []
    if cnt == 0:
        print 'IPv4 addresses will not be added in file'
    else:
        if flg == False:
            print 'Start of generation of real IPv4 addresses'
            for _ in range(cnt):
                octet1 = octet2 = octet3 = octet4 = 0
                octet1 = randint(1, 223)
                if octet1 in (10, 127, 172, 192):
                    octet1 = octet1 + 1
                octet2 = randint(0, 255)
                octet3 = randint(0, 255)
                octet4 = randint(1, 254)
                ip4_list.append(str(octet1)+'.'+str(octet2)+'.'+str(octet3)+'.'+str(octet4))
        else:
            print 'Start of generation of grey IPv4 addresses'
            private_network_first_octet = [10, 172, 192]
            for _ in range(cnt):
                octet1 = octet2 = octet3 = octet4 = 0
                octet1 = choice(private_network_first_octet)
                if octet1 == 192:
                    octet2 = 168
                elif octet1 == 172:
                    octet2 = randint(16, 32)
                else:
                    octet2 = randint(0, 255)
                octet3 = randint(0, 255)
                octet4 = randint(1, 254)
                ip4_list.append(str(octet1)+'.'+str(octet2)+'.'+str(octet3)+'.'+str(octet4))
    
    return ip4_list

### =================================================================
def generate_ip6(cnt):

    ip6_list = []
    if cnt == 0:
        print 'IPv6 addresses will not be added in file'
    else:
        print 'Start of generation of IPv6 addresses'
        i = 0
        for _ in range(cnt):
            ip6_list.append("2001:"+":".join(("%x" % randint(0, 65536) for j in range(7))))
    return ip6_list

### =================================================================
def generate_domain(cnt):
    # initial TLD - one day they will be moved out in external file
    tld0 = ['en', 'ru', 'ua']
    tld1 = ['com', 'net', 'gov']

    dom_list = []
    if cnt == 0:
        print 'Domains will not be added in file'
    else:
        print 'Start of generation of Domains'
        for i in range(cnt):
            dom = ''
            for j in range(10): ### there is length of domain name
                dom = dom+choice(letters[:26])
            domain_level_0 = choice(tld0)
            domain_level_1 = choice(tld1)
            dom = dom+'.'+domain_level_1+'.'+domain_level_0
            dom_list.append(dom)
    return dom_list

### =================================================================
def store_in_file(flg, fnm, ip4_data, ip6_data, dom_data):
    """
      flg - flag that shows create all items in one file (false) or separete it by type (True)
      fnm - file name
    """
    if flg == False:
        for fff in os.listdir("./"):
            if fff == fnm:
                fnm = fnm+str(1)
        print "Start of writing items in file %s" % fnm
        with open(fnm, 'w') as f:
            for line in ip4_data:
                print >> f, line
            for line in ip6_data:
                print >> f, line
            for line in dom_data:
                print >> f, line
    else:
        for fff in os.listdir("./"):
            if (fff.split('.')[0]) == fnm:
                fnm = fnm+str(1)   
        print "Start of writing items in separate files: %s.ip4, %s.ip6, %s.dom" % (fnm, fnm, fnm)
        with open(fnm+".ip4", 'w') as f:
            for line in ip4_data:
                print >> f, line
        with open(fnm+".ip6", 'w') as f:
            for line in ip6_data:
                print >> f, line
        with open(fnm+".dom", 'w') as f:
            for line in dom_data:
                print >> f, line
### ==================================================================
if __name__ == '__main__':
    
    ip4_feed = generate_ip4(options.ip4_cnt, options.ip_type)
    ip6_feed = generate_ip6(options.ip6_cnt)
    dom_feed = generate_domain(options.dom_cnt)
    
    store_in_file (options.separate, options.filename, ip4_feed, ip6_feed, dom_feed)
