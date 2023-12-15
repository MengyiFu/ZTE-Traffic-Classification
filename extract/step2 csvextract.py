import os
import socket
import time

import dpkt

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
    if srcip < dstip:
        tuple5 = srcip + ',' + str(srcport) + ',' + dstip + ',' + str(dstport) + ',' + str(protocol_index)
    else:
        tuple5 = dstip + ',' + str(dstport) + ',' + srcip + ',' + str(srcport) + ',' + str(protocol_index)
    return tuple5

def preprocesstext(pairfile, predictfile):
    with open(pairfile, 'r') as file:
        lines = file.readlines()

    with open(predictfile, 'w') as file:
        for line in lines:
            if 'In recvTcpMsg, func readn() err peer closed:' not in line and 'Waiting for client connection.' not in line:
                file.write(line)


# 应用名称：应用版本， 不含_
appname_ver = {"王者荣耀": "9.1.1.1", "QQ音乐": "12.3.5.8", "腾讯视频": "8.9.30.27684", "金铲铲之战": "1.5.14",
               "哔哩哔哩": "7.47.0", "QQ飞车": "1.39.0.35232", "虎牙直播": "11.4.3", "腾讯会议": "3.19.22(423)",
               "百度贴吧": "12.42.5.0", "中国大学MOOC": "4.26.0", "抖音": "27.0.0", "香肠派对": "16.14",
               "崩坏：星穹铁": "1.3.0", "原神": "4.1.0", "和平精英": "1.24.23", "作业帮": "13.57.0",
               "优酷视频": "11.0.48", "淘宝": "10.28.20", "快手": "11.8.40.33234", "芒果TV": "7.5.4",
               "英雄联盟手游": "4.4.0.7363", "中视慧云": "3.4.4", "央视影音HD": "7.6.3", "咪咕视频": "6.1.7.50",
               "搜狐视频": "9.9.13", "网易云音乐": "8.10.80", "钉钉": "7.1.2", "明日方舟": '2.1.01',
               "决战！平安京": '1.161.0', "爱奇艺": "14.7.5", "蛋仔派对": '1.0.105',"第五人格":"1.5.91","碧蓝航线":"7.1.1","斗鱼":"7.5.2"}
# 目标应用
targetapp = ['哔哩哔哩', '王者荣耀', 'QQ音乐', '腾讯视频', '金铲铲之战', '哔哩哔哩', '虎牙直播', '腾讯会议', '百度贴吧',
             '中国大学MOOC', '抖音', 'QQ飞车', '香肠派对', '崩坏：星穹铁', '原神', '和平精英', '作业帮', '优酷视频',
             '淘宝', '快手', '芒果TV', '英雄联盟手游', '中视慧云', '央视影音HD', '咪咕视频', '搜狐视频', '网易云音乐',
             '钉钉', '明日方舟', '决战！平安京', '蛋仔派对',"第五人格","碧蓝航线","爱奇艺","斗鱼"]
# targetapp = ['百度贴吧', '腾讯会议', '王者荣耀', '腾讯视频', '网易云音乐', '淘宝', '原神', '哔哩哔哩', '金铲铲之战', '爱奇艺', '香肠派对', '和平精英']

# 文件夹位置
csvpath = './raspberrypi_csv/'
APpath = './pcapdroid/'
extractpath = './extractcsv/'

chargeperson = 'fmy'
vrip = '192.168.2.6'


if __name__ == '__main__':
    # 遍历pcapdorid，提取五元组：应用名
    tuple5_appname = {}
    APpathlist = walkfile(APpath)
    for file in APpathlist:
        f = open(file, mode='rb')
        print("正在读取文件：", file)

        pkts = dpkt.pcap.Reader(f)
        idx = 1
        for ts, buf in pkts:

            # print('数据包数：', idx)
            idx = idx + 1
            # 提取IP五元组
            try:
                tuple5 = gettuple5()
            except NameError:
                continue
            # print('tuple5:', tuple5)

            # 提取应用名称
            pcapdroiddata = buf[-32:]
            # print('pcapdroiddata:', pcapdroiddata)

            applabel = pcapdroiddata[8: 28]
            # print('applabel:', applabel)

            appname = applabel.decode('utf-8', errors='ignore').strip(b'\x00'.decode()).replace(' ', '')
            print('appname:', appname)

            tuple5_appname[tuple5] = appname
            # print('app5tuple:', tuple5_appname)

        f.close()
    # print(tuple5_appname)


    # 遍历ubuntu csv
    filename_pkts = {}
    csvpathlist = walkfile(csvpath)
    localtime = time.strftime('%Y%m%d%H%M%S', time.localtime())
    idx = 0
    for file in csvpathlist:
        # 提取五元组
        f = open(file, mode='r')
        print("正在读取文件：", file)

        for line in f:

            # print('数据包数：', idx)
            idx = idx + 1

            # 提取99个特征
            feature99 = line.split(',')[5:]
            if len(feature99) != 1:
                feature99 = ','.join(feature99)
            else:
                continue
            print('feature99:', feature99)

            # 提取IP五元组
            tuple5 = line.split(',')[0: 5]
            tuple5 = ','.join(tuple5)
            # print('tuple5:', tuple5)

            # 获取五元组对应的应用名称
            if tuple5 in tuple5_appname.keys():
                flag = True
                appname = tuple5_appname[tuple5]
            else:
                flag = False

            if flag:
                if appname in targetapp:
                    filename = extractpath + appname + '_target_' + appname_ver[appname] + '_Android_' + localtime + '_' + chargeperson + '.csv'
                else:
                    filename = extractpath + appname + '_background_v99.99_Android_' + localtime + '_' + chargeperson + '.csv'
                print('filename: ', filename)

                # 写入字典，应用名称：[99个特征1, 99个特征2, ...]
                if filename in filename_pkts.keys():
                    filename_pkts[filename] += [feature99]
                else:
                    filename_pkts[filename] = [feature99]
                # print('appfeature:', filename_pkts[filename])

            else:
                if vrip in tuple5:
                    filename = extractpath + 'VR_target_v99.99_Android_' + localtime + '_' + chargeperson + '.csv'
                    # print('VR匹配上,并存入', filename)
                    print(tuple5)

                    # 写入字典，应用名称：[99个特征1, 99个特征2, ...]
                    if filename in filename_pkts.keys():
                        filename_pkts[filename] += [feature99]
                    else:
                        filename_pkts[filename] = [feature99]
                    # print('appfeature:', filename_pkts[filename])

        f.close()

        for key in filename_pkts.keys():
            f = open(key, 'a')
            print('正在写入文件：', key)
            for line in filename_pkts[key]:
                print(line)
                f.write(line)
            f.close()
