#!/usr/bin/env python2

import os
import pickle
import struct
import socket
from operator import itemgetter
import geoip2.database

def read_geoip(IP, reader):
    """ get the geo pip information
        return city name, states, lat, lon
    """
    response = None
    try:
        response = reader.city(IP)
    except geoip2.errors.AddressNotFoundError:
        return None, None, None, None
    if response:
        return  response.city.name, response.subdivisions.most_specific.name,\
                response.location.latitude, response.location.longitude

def inBlock(IP, Prefix, Mask):
    """test if a IP is in a IP block"""
    ip = struct.unpack('!L',\
        socket.inet_aton(IP))[0] & ((2L<<31) - (2L<<(31-Mask)))
    prefix = struct.unpack('!L', socket.inet_aton(Prefix))[0]
    return ip == prefix

def isGoogleIP(IP):
    return inBlock(IP, "64.18.0.0", 20) or inBlock(IP, "64.233.160.0", 19) or\
    inBlock(IP, "66.249.80.0", 20) or inBlock(IP, "66.102.0.0", 20) or\
    inBlock(IP, "72.14.192.0", 18) or inBlock(IP, "74.125.0.0", 16) or\
    inBlock(IP, "108.177.8.0", 21) or inBlock(IP, "173.194.0.0", 16) or\
    inBlock(IP, "207.126.144.0", 20) or inBlock(IP, "209.85.128.0", 17) or\
    inBlock(IP, "216.58.192.0", 19) or inBlock(IP, "216.239.32.0", 19)

def findCenter(seen):
    """ a heristic approach to find the geo-center of many coordinates
        with noise. It calulcates the geo-center of all coordinates
        then get rid of the farthest 25 percent of them, then re-compute
        for the remaining coordinates.
        NOTE: mathimatical average and gaussian distance are just
        approximations for geographic latitude and longitude
    """
    avg_lat = 0
    avg_lon = 0
    names = {} # record every state name only once
    label = u""
    for city in seen:
        if city[3]:
            names[city[3]] = 1
        avg_lat += city[1]
        avg_lon += city[2]
    avg_lat = avg_lat/len(seen)
    avg_lon = avg_lon/len(seen)
    for name in names:
        label = label + ";" + name
    if len(seen) < 4:
        return avg_lat, avg_lon, label

    candidates = []
    for city in seen:
        dist = (city[1] - avg_lat)**2 + (city[2] - avg_lon)**2
        candidates.append((city[0], city[1], city[2], city[3], dist))

    sorted_candidates = sorted(candidates, key=itemgetter(4))
    sorted_candidates = sorted_candidates[:int(0.75*len(sorted_candidates))]

    avg_lat = 0
    avg_lon = 0
    for candidate in sorted_candidates:
        avg_lat += candidate[1]
        avg_lon += candidate[2]
    avg_lat = avg_lat/len(sorted_candidates)
    avg_lon = avg_lon/len(sorted_candidates)

    return avg_lat, avg_lon, label

CACHE_FILE = os.path.abspath(r"./mapping.db")

def main():
    READER = geoip2.database.Reader('.geoip/GeoLite2-City.mmdb')
    print "server,cities,names,lat,lon"
    with open(CACHE_FILE, 'rb') as f:
        pool = pickle.load(f)

    for server in pool:
        seen = []
        for client in pool[server]:
            if isGoogleIP(client[0]):
                continue
            city, sub, lat, lon = read_geoip(client[0], READER)
            if city:
                seen.append((city, lat, lon, sub))
        if len(seen) == 0:
            continue
        avg_lat, avg_lon, label = findCenter(seen)
        try:
            print server + ',' + str(len(seen)) + ',' +\
                    label.encode('ascii', 'ignore') +\
                    ',' + str(avg_lat) + ',' + str(avg_lon)
        except UnicodeEncodeError as e:
            # XXX: some city names have unicode chars which
            # cause error. Why python cannot handle unicode?
            print "error", label, e

    READER.close()

if __name__ == '__main__':
    main()
