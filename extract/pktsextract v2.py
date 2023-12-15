import os
import socket
import time
import dpkt
import IPy
# 遍历文件
def walkfile(file):
    filepatlist = []
    for root, dirs, files in os.walk(file):
        # root 表示当前访问的文件夹路径
        # dirs 表示该文件夹下的子目录名list
        # files 表示该文件夹下的文件list
        for f in files:
            filepath = os.path.join(root, f)
            filepatlist.append(filepath)
    return filepatlist


def gettuple5():
    global srcip, dstip, protocol_index, srcport, dstport
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
    # 五元组
    int_srcip = IPy.IP(srcip).int()
    used_srcip = socket.htonl(int_srcip)

    int_dstip = IPy.IP(dstip).int()
    used_dstip = socket.htonl(int_dstip)
    if used_srcip > used_dstip:
        tuple5 = srcip + ',' + str(srcport) + ',' + dstip + ',' + str(dstport) + ',' + str(protocol_index)
    else:
        tuple5 = dstip + ',' + str(dstport) + ',' + srcip + ',' + str(srcport) + ',' + str(protocol_index)
    return tuple5

# # 应用名称：应用版本
# appname_ver = {'百度贴吧': 0, '腾讯会议': 1, '英雄联盟手游': 2,'腾讯视频': 3, '网易云音乐': 4, '淘宝': 5, '原神': 6,'哔哩哔哩':7,'金铲铲之战':8,'爱奇艺':9,'香肠派对':10,'和平精英':11}
# # 目标应用
# targetapp = ['百度贴吧','腾讯会议','英雄联盟手游','腾讯视频','网易云音乐','淘宝','原神','哔哩哔哩','金铲铲之战','爱奇艺','香肠派对','和平精英']
# 应用名称：应用版本
appname_ver = {'王者荣耀': 2}
targetapp = ['王者荣耀']
# pcapdroid文件位置
APpath = './pcapdroid/'
# 提纯的pcap文件位置
extractpath = './extractpcap/'
chargeperson = 'fmy'


if __name__ == '__main__':
    # 创建字典存储包，形式为{'文件名': [包列表]}
    filename_pkts = {}
    APpathlist = walkfile(APpath)
    localtime = time.strftime('%Y%m%d%H%M%S', time.localtime())
    for file in APpathlist:
        f = open(file, mode='rb')
        print("正在读取文件：", file)

        pkts = dpkt.pcap.Reader(f)
        idx = 1
        for ts, buf in pkts:

            # # print('数据包数：', idx)
            # idx = idx + 1

            # 提取应用名称
            pcapdroiddata = buf[-32:]
            # print('pcapdroiddata:', pcapdroiddata)

            applabel = pcapdroiddata[8: 28]
            # print('applabel:', applabel)

            appname = applabel.decode('utf-8', errors='ignore').strip(b'\x00'.decode())
            # print('appname:', appname)

            if appname in targetapp:
                filename = extractpath + appname + '_target_' + str(appname_ver[
                    appname]) + '_Android_' + localtime + '_' + chargeperson + '.pcap'
            else:
                filename = extractpath + appname + '_background_v99.99_Android_' + localtime + '_' + chargeperson + '.pcap'
            # print('filename: ', filename)

            # 写入字典，应用名称：[数据包1, 数据包2, ...]
            if filename in filename_pkts.keys():
                filename_pkts[filename] += [[buf, ts]]
            else:
                filename_pkts[filename] = [[buf, ts]]

        f.close()
    # print(filename_pkts)

    for key in filename_pkts.keys():
        f = open(key, 'wb')
        pw = dpkt.pcap.Writer(f)
        print('正在写入文件：', key)
        for buf, ts in filename_pkts[key]:
            # print(buf, ts)
            pw.writepkt(buf, ts)








