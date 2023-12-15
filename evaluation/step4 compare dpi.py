import json
import os
import time

import IPy
import dpkt
import socket
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.font_manager as fm

from sklearn.metrics import classification_report, confusion_matrix
from dnsprocess import ipdnsdirect, IP_DNS_DIRECT


def walkFile(file):
    filepatlist = []
    for root, dirs, files in os.walk(file):
        # root 表示当前访问的文件夹路径
        # dirs 表示该文件夹下的子目录名list
        # files 表示该文件夹下的文件list
        for f in files:
            filepath = os.path.join(root, f)
            filepatlist.append(filepath)
    return filepatlist


# 读取pcapdroid抓取的pcap文件
def createfrompcap(pcapfile):
    srcip = ''
    dstip = ''
    srcport = 0
    dstport = 0
    protocol_index = 0
    flow_unique = set()
    flowinpcap = []

    f = open(pcapfile, mode='rb')
    print("正在读取文件：", pcapfile)

    # dpkt解析数据包
    pkts = dpkt.pcap.Reader(f)
    for ts, buf in pkts:

        # 提取IP五元组
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            srcip = socket.inet_ntoa(ip.src)
            dstip = socket.inet_ntoa(ip.dst)
            protocol_index = ip.p
            if isinstance(ip.data, dpkt.tcp.TCP) or isinstance(ip.data, dpkt.udp.UDP):
                srcport = ip.data.sport
                dstport = ip.data.dport
        elif isinstance(eth.data, dpkt.ip6.IP6):
            ipv6 = eth.data
            srcip = socket.inet_ntop(socket.AF_INET6, ipv6.src)
            dstip = socket.inet_ntop(socket.AF_INET6, ipv6.dst)
            protocol_index = ipv6.nxt
            if isinstance(ipv6.data, dpkt.tcp.TCP) or isinstance(ipv6.data, dpkt.udp.UDP):
                srcport = ipv6.data.sport
                dstport = ipv6.data.dport

        # 提取应用名称
        pcapdroiddata = buf[-32:]
        # print('pcapdroiddata:', pcapdroiddata)
        applabel = pcapdroiddata[8: 28]
        # print('applabel:', applabel)
        appname = applabel.decode('utf-8', errors='ignore').strip(b'\x00'.decode()).replace(' ', '')
        # print('appname:', appname)
        if appname in target_applabel.keys():
            label = target_applabel[appname]
        else:
            # 其他类:
            # label = len(targetname) - 1
            label = len(targetname) - 1


        int_srcip = IPy.IP(srcip).int()
        used_srcip = socket.htonl(int_srcip)

        int_dstip = IPy.IP(dstip).int()
        used_dstip = socket.htonl(int_dstip)
        if used_srcip > used_dstip:
            key = srcip + ',' + str(srcport) + ',' + dstip + ',' + str(dstport) + ',' + str(protocol_index)
        else:
            key = dstip + ',' + str(dstport) + ',' + srcip + ',' + str(srcport) + ',' + str(protocol_index)

            # 只取同一条流的第一条流
            if key not in flow_unique and srcip not in IP_DNS_DIRECT.keys() and dstip not in IP_DNS_DIRECT.keys():
                flow_unique.add(key)
                # 一条流记录[五元组, 真实标签]
                flowinpcap.append([key, label])

    f.close()
    print("文件中流量条数：", len(flowinpcap))
    return flowinpcap



# 读取路由器的预测结果
def createfromtext(textfile):
    flowintext = []
    f = open(textfile, mode='r')
    print("正在读取文件：", textfile)
    for line in f:
        # 逗号分割，分别获取对应值
        srcip, srcport, dstip, dstport, protocol_index, label, confidence = line.strip().split(',')
        label = label.split(':')[-1].strip()
        protocol_index = protocol_index.split('.')[0]
        dstport = dstport.split('.')[0]

        if srcip < dstip:
            key = srcip + ',' + srcport + ',' + dstip + ',' + dstport + ',' + protocol_index
        else:
            key = dstip + ',' + dstport + ',' + srcip + ',' + srcport + ',' + protocol_index

        # 一条流记录[五元组, 预测标签, 置信度]
        flowintext.append([key, int(label), float(confidence)])

    f.close()
    return flowintext


target_applabel = {'王者荣耀': 2}
targetname = ['王者荣耀']

# 带标记流量文件位置
pcappath = './apppcap/'
# AI预测
aipath = './prediction.txt'
# DPI匹配
dpipath = './dpiprediction.txt'



if __name__ == '__main__':
    pcappathlist = walkFile(pcappath)

    # 王者荣耀真实流
    pcapcatch_flow = []
    for pcapfile in pcappathlist:
        # 读取真实流pcap
        pcapcatch_flow += createfrompcap(pcapfile)

    # AI识别王者荣耀对的流
    ai_true = []
    # AI预测流
    ai_prediction = createfromtext(aipath)

    # 遍历pcapdroid真实流
    for pcf in pcapcatch_flow:
        # pcf = [五元组, 真实标签]
        # 遍历预测流
        for pf in ai_prediction:
            # pf = [五元组, 预测标签, 置信度]
            # 如果五元组匹配成功,则说明两个都有
            if pf[0] == pcf[0] and pf[1] == 2:
                ai_true.append(pf[0])
    ai_true_set = set(ai_true)
    print('ai_true:{}, ai_true_set:{}'.format(len(ai_true), len(ai_true_set)))

    # DPI识别王者荣耀对的流
    dpi_true = []
    # dpi预测流
    dpi_prediction = createfromtext(dpipath)

    # 遍历pcapdroid真实流
    for pcf in pcapcatch_flow:
        # pcf = [五元组, 真实标签]
        # 遍历预测流
        for pf in dpi_prediction:
            # pf = [五元组, 预测标签, 置信度]
            # 如果五元组匹配成功,则说明两个都有
            if pf[0] == pcf[0]:
                dpi_true.append(pf[0])
    dpi_true_set = set(dpi_true)
    print('dpi_true:{}, dpi_true_set:{}'.format(len(dpi_true), len(dpi_true_set)))

    interset = ai_true_set & dpi_true_set
    unionset = ai_true_set | dpi_true_set
    groundtruth = []
    for f in pcapcatch_flow:
        if '192.168.100.161' in f[0]:
            groundtruth.append(f[0])
    gtset = set(groundtruth)
    print('groundtruth:{}, gtset:{}'.format(len(groundtruth), len(gtset)))
    print('交集:{}, 并集:{}, 王者荣耀:{}'.format(len(interset), len(unionset), len(gtset)))