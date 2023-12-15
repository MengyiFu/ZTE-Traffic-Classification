# 提取pcapdroid包中tls/http/https/dns对应的五元组
import json
import os
import socket

import IPy


MERCURY_KEY = []

def mercury_cmd(pcappathlist):
    for pcap in pcappathlist:
        cmd = "./mercury -r %s --certs-json --dns-json --metadata >>./data/mercury.json"
        command = cmd % pcap
        os.system(command)

def ip_compare(srcip, dstip):
    srcip6 = IPy.IP(srcip)
    srcip6_0 = (srcip6.ip >> 96) & 0xffffffff
    srcip6_1 = (srcip6.ip >> 64) & 0xffffffff
    srcip6_2 = (srcip6.ip >> 32) & 0xffffffff
    srcip6_3 = srcip6.ip & 0xffffffff
    srcnet6_0 = socket.htonl(srcip6_0)
    srcnet6_1 = socket.htonl(srcip6_1)
    srcnet6_2 = socket.htonl(srcip6_2)
    srcnet6_3 = socket.htonl(srcip6_3)

    dstip6 = IPy.IP(dstip)

    dstip6_0 = (dstip6.ip >> 96) & 0xffffffff
    dstip6_1 = (dstip6.ip >> 64) & 0xffffffff
    dstip6_2 = (dstip6.ip >> 32) & 0xffffffff
    dstip6_3 = dstip6.ip & 0xffffffff

    dstnet6_0 = socket.htonl(dstip6_0)
    dstnet6_1 = socket.htonl(dstip6_1)
    dstnet6_2 = socket.htonl(dstip6_2)
    dstnet6_3 = socket.htonl(dstip6_3)
    result = srcnet6_0 > dstnet6_0 or srcnet6_1 > dstnet6_1 or srcnet6_2 > dstnet6_2 or srcnet6_3 > dstnet6_3
    return result


def get_mercury_key(pcappathlist, mercury_path):
    global MERCURY_KEY
    if os.path.exists(mercury_path):
        os.remove(mercury_path)
    mercury_cmd(pcappathlist)
    with open('data/mercury.json', 'r') as file:
        mercury_json = [json.loads(line.strip()) for line in file]

    for json_obj in mercury_json:
        flag = json_obj.keys() & {'tls', 'http', 'https', 'dns'}
        if flag:
            srcip = json_obj['src_ip']
            dstip = json_obj['dst_ip']
            srcport = str(json_obj['src_port'])
            dstport = str(json_obj['dst_port'])
            protocol_index = str(json_obj['protocol'])
            if ip_compare(srcip, dstip):
                key = srcip + ',' + srcport + ',' + dstip + ',' + dstport + ',' + protocol_index
            else:
                key = dstip + ',' + dstport + ',' + srcip + ',' + srcport + ',' + protocol_index
            MERCURY_KEY.append(key)
            # print(key)