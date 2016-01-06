#!/usr/bin/env python2

import struct
import socket
import os
import pickle
import time
import argparse
from threading import Thread
import dns
import clientsubnetoption
import geoip2.database

# public DNS servers that support EDNS0
DNS_servers = ['8.8.8.8', '8.8.4.4']

# save intermediate and final results to disk
CACHE_FILE = os.path.abspath(r"./mapping.db")
# the next IP to scan
NOW_FILE = os.path.abspath(r"./now.db")

# domain names and CDN that support EDNDS0 so far are
#gp1.wac.v2cdn.net maxCDN
#dl47xs20witg8.cloudfront.net  cloudfront
#gp1.wac.v2cdn.net edgecast
#www.google.com google
CDN = {\
        'google': 'www.google.com',
        'edgecast': 'gp1.wac.v2cdn.net',
        'cloudfront': 'dl47xs20witg8.cloudfront.net',
        'maxCDN': 'gp1.wac.v2cdn.net'
      }
CDNNames = ""
for name in CDN:
    CDNNames += name + ' '


def networkMask(ip, bits):
    """compute the masked IP prefix, return IP string"""
    ip_prefix = struct.unpack('!L',\
        socket.inet_aton(ip))[0] & ((2L<<31) - (2L<<(31-bits)))
    return socket.inet_ntoa(struct.pack('!L', ip_prefix))

def advance(ip_binary, bits):
    """ Jump to the next ip prefix accross the current bits as IP mask"""
    ip_binary = ip_binary & ((2L<<31) - (2L<<(31-bits)))
    ip_binary += 1<<(32-bits)
    return ip_binary

def good_IP(IP, reader):
    """ test if the IP (in string) is a public IP
        according to the geo IP database
    """
    response = None
    try:
        response = reader.city(IP)
    except geoip2.errors.AddressNotFoundError:
        return False
    if response:
        return response.city.name is not None

def inBlock(IP_binary, Prefix, Mask):
    """test if a IP (in binary) is within the prefix (in string) + mask"""
    ip = IP_binary & ((2L<<31) - (2L<<(31-Mask)))
    prefix = struct.unpack('!L', socket.inet_aton(Prefix))[0]
    return ip == prefix

def isGoogleIP(IP):
    """ test if a IP is google IP
        if true, return the prefix to advance over it
        google IP ranges are retrieved by
        'nslookup -q=TXT _netblocks.google.com 8.8.8.8'
    """
    if inBlock(IP, "64.18.0.0", 20) or inBlock(IP, "207.126.144.0", 20) or\
    inBlock(IP, "66.102.0.0", 20) or inBlock(IP, "66.249.80.0", 20):
        return 20
    if inBlock(IP, "108.177.8.0", 21):
        return 21
    if inBlock(IP, "72.14.192.0", 18):
        return 18
    if inBlock(IP, "74.125.0.0", 16) or inBlock(IP, "173.194.0.0", 16):
        return 16
    if inBlock(IP, "209.85.128.0", 17):
        return 17
    if inBlock(IP, "216.58.192.0", 19) or inBlock(IP, "216.239.32.0", 19) or\
        inBlock(IP, "64.233.160.0", 19):
        return 19
    return 0

def save_states(pool, now):
    """ save the mapping and current IP"""
    try:
        f = open(CACHE_FILE, 'w')
        pickle.dump(pool, f)
    finally:
        f.close()
    try:
        f = open(NOW_FILE, 'w')
        pickle.dump(now, f)
    finally:
        f.close()



def main(arguments):

    # default: start from 1.0.0.0
    IP_binary = struct.unpack('!L', socket.inet_aton(arguments.start))[0]
    step = 24 # /24 is the minium step

    mask = step
    suggested_mask = step # the mask suggested by DNS response

    pool = {} # the mapping results

    count = 1
    timeout = 0
    failed = 0
    isFailed = False

    # first, restore the current states from last time
    if os.path.isfile(CACHE_FILE):
        with open(CACHE_FILE, 'rb') as f:
            pool = pickle.load(f)

    if os.path.isfile(NOW_FILE):
        with open(NOW_FILE, 'rb') as f:
            IP_binary = pickle.load(f)
    # load geo ip data
    READER = geoip2.database.Reader('./geoip/GeoLite2-City.mmdb')

    # main loop over all IPs
    while IP_binary < 255*(1<<24): #255.0.0.0
        IP_pack = struct.pack('!L', IP_binary)
        IP = socket.inet_ntoa(IP_pack)

        # skip private IP
        if not good_IP(IP, READER):
            IP_binary = advance(IP_binary, mask)
            continue
        # skip google IP as their locations are all reported as MTV
        googlemask = isGoogleIP(IP_binary)
        if googlemask > 0:
            IP_binary = advance(IP_binary, googlemask)
            continue
        # creat the query message
        cso = clientsubnetoption.ClientSubnetOption(IP, bits=mask)
        # default: 'google'
        message = dns.message.make_query(CDN[arguments.name], 'A')
        message.use_edns(options=[cso])
        try:
            # rotating the DNS server we use
            r = dns.query.udp(message,
                              DNS_servers[count%len(DNS_servers)],
                              timeout=arguments.timeout)
        except dns.exception.Timeout:
            timeout += 1
            print 'timeout:', DNS_servers[count%len(DNS_servers)], IP
            IP_binary = advance(IP_binary, mask)
            continue

        # only use A record here because it seems enough
        servers = {}
        for ans in r.answer:
            if ans.to_rdataset().rdtype == dns.rdatatype.A:
                # use /24 prefix to represent
                # all the servers in the same location
                server = networkMask(ans[0].to_text(), 24)
                servers[server] = 1

        # if ENDS0 is used, get the suggested mask.
        for options in r.options:
            if isinstance(options, clientsubnetoption.ClientSubnetOption):
                suggested_mask = int(options.scope)

        if len(servers) > 0:
            for server in servers:
                clients = pool.get(server, [])
                clients.append((IP, suggested_mask))
                pool[server] = clients
                isFailed = False
        else:
            failed += 1
            print  r.answer
            print 'failed:', DNS_servers[count%len(DNS_servers)],\
                            IP, suggested_mask
            isFailed = True

        if suggested_mask == 0:
            # suggested == 0 *might* imply EDNS0 is not supported
            mask = step
        elif suggested_mask == 32:
            # suggested == 0 *might* imply
            # the EDNS0 record for this prefix is not set
            mask = 17 # rule of thumb: take a big step forward
        else:
            mask = suggested_mask

        IP_binary = advance(IP_binary, mask)
        count += 1

        # save and report every 500 prefixes
        if count % 500 == 0:
            print IP, mask, suggested_mask
            print "Servers %d, errors %d/%d"%(len(pool), timeout, failed)
            # start another thread to save so that it will not be interrupted
            # by signals such as ctrl+c
            a = Thread(target=save_states, args=(pool, IP_binary))
            a.start()
            a.join()
        if isFailed:
            # might need to slow down because we sent too many requests
            # rule of thumb: 90 seconds should be enough
            time.sleep(arguments.cooldown)
        else:
            time.sleep(arguments.delay)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(\
                    formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                    description='Point of Presence Crawler')
    parser.add_argument('-n', '--name', default='google',
                        help='the CDN to crawl, options are %s'%CDNNames)
    parser.add_argument('-d', '--delay', type=float, default=0.1,\
                        help='Seconds to sleep between normal DNS queries')
    parser.add_argument('-c', '--cooldown', type=float, default=90,\
                        help='Seconds to sleep when DNS deny to respond')
    parser.add_argument('-t', '--timeout', type=float, default=0.5,\
                        help='timeout(in seconds) to wait for a DNS response')
    parser.add_argument('-s', '--start', default='1.0.0.0',
                        help='the IP address to start if now.db is not present')
    parser.add_argument('-q', '--quiet', action='store_true', default=False,\
                        help='only print errors (not implemented yet)')
    args = parser.parse_args()
    main(args)
