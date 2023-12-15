import ipaddress
import json
import os
import time
import IPy
import dpkt
import socket
#import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
#import seaborn as sns
import matplotlib.font_manager as fm

from sklearn.metrics import classification_report, confusion_matrix
from dnsprocess import ipdnsdirect, IP_DNS_DIRECT
from fig_plot import threshold09_hist, threshold_hist, report_bar, report_pie, ratios_confusion_matrix, max_truepredict, \
    max_mispredict
from mercury_process import MERCURY_KEY, get_mercury_key


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

        try:
            ipaddress.IPv4Address(srcip)
            ipaddress.IPv4Address(dstip)
        except ValueError:
            continue

        if ip_compare(srcip, dstip):
            key = srcip + ',' + str(srcport) + ',' + dstip + ',' + str(dstport) + ',' + str(protocol_index)
        else:
            key = dstip + ',' + str(dstport) + ',' + srcip + ',' + str(srcport) + ',' + str(protocol_index)

        # 只取同一条流的第一条流,加一个判断，是否在tls的五元组列表中
        if key not in flow_unique and srcip not in IP_DNS_DIRECT.keys() and dstip not in IP_DNS_DIRECT.keys() and key not in MERCURY_KEY:
            flow_unique.add(key)
            # 一条流记录[五元组, 真实标签]
            flowinpcap.append([key, label])

    f.close()
    print("文件中流量条数：", len(flowinpcap))
    return flowinpcap


def createfrompair(predfile):
    with open(predfile, 'r') as file:
        lines = file.readlines()

    prediction_flow = []

    for i in range(0, len(lines), 2):
        # 读取特征行
        feature_line = lines[i]
        features = feature_line.split(',')[5:]
        features = ','.join(features)

        # 读取预测流
        tuple_line = lines[i + 1]
        srcip, srcport, dstip, dstport, protocol_index, label, confidence = tuple_line.strip().split(',')
        label = label.split(':')[-1].strip()
        protocol_index = protocol_index.split('.')[0]
        dstport = dstport.split('.')[0]

        if srcip not in IP_DNS_DIRECT.keys() and dstip not in IP_DNS_DIRECT.keys():
            if srcip < dstip:
                key = srcip + ',' + srcport + ',' + dstip + ',' + dstport + ',' + protocol_index
            else:
                key = dstip + ',' + dstport + ',' + srcip + ',' + srcport + ',' + protocol_index

            prediction_flow.append([key, int(label), float(confidence), features])
    return prediction_flow


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

        try:
            ipaddress.IPv4Address(srcip)
            ipaddress.IPv4Address(dstip)
        except ValueError:
            continue

        if ip_compare(srcip, dstip):
            key = srcip + ',' + srcport + ',' + dstip + ',' + dstport + ',' + protocol_index
        else:
            key = dstip + ',' + dstport + ',' + srcip + ',' + srcport + ',' + protocol_index

        if key not in MERCURY_KEY:
        # 一条流记录[五元组, 预测标签, 置信度]
            flowintext.append([key, int(label), float(confidence)])

    f.close()
    return flowintext


def preprocesstext(pairfile, predictfile):
    with open(pairfile, 'r') as file:
        lines = file.readlines()

    with open(predictfile, 'w') as file:
        for line in lines:
            if 'In recvTcpMsg, func readn() err peer closed:' not in line and 'Waiting for client connection.' not in line:
                file.write(line)


# target_applabel = {'王者荣耀': 2}
# targetname = ['王者荣耀']
# 5app
target_applabel = {'王者荣耀': 0, '英雄联盟手游': 1,'原神':2, '金铲铲之战': 3,'香肠派对': 4, '和平精英': 5, '崩坏：星穹铁': 6, '蛋仔派对': 7,'腾讯视频':8,'爱奇艺':9,'哔哩哔哩':10,'抖音':11,'快手':12,'斗鱼':13,'腾讯会议': 14,'百度贴吧':15,'中国大学MOOC':16,'作业帮':17,'网易云音乐':18,'淘宝':19}
#target_applabel = {'百度贴吧': 0, '腾讯会议': 1, '王者荣耀':2, '英雄联盟手游': 3,'腾讯视频': 4, '网易云音乐': 5, '淘宝': 6,'哔哩哔哩':8,'金铲铲之战':9,'爱奇艺':10,'香肠派对':11,'和平精英':12}
#target_applabel_compare = {'百度贴吧': 0, '腾讯会议': 1, '王者荣耀':2, '英雄联盟手游': 3,'腾讯视频': 4, '网易云音乐': 5, '淘宝': 6, '原神': 7,'哔哩哔哩':8,'金铲铲之战':9,'爱奇艺':10,'香肠派对':11,'和平精英':12,'背景':13}
target_applabel_compare ={'王者荣耀': 0, '英雄联盟手游': 1,'原神':2, '金铲铲之战': 3,'香肠派对': 4, '和平精英': 5, '崩坏：星穹铁': 6, '蛋仔派对': 7,'腾讯视频':8,'爱奇艺':9,'哔哩哔哩':10,'抖音':11,'快手':12,'斗鱼':13,'腾讯会议': 14,'百度贴吧':15,'中国大学MOOC':16,'作业帮':17,'网易云音乐':18,'淘宝':19,'背景':20}
#targetname = ['百度贴吧','腾讯会议','王者荣耀','英雄联盟手游','腾讯视频','网易云音乐','淘宝','原神','哔哩哔哩','金铲铲之战','爱奇艺','香肠派对','和平精英','背景']
targetname = ['王者荣耀','英雄联盟手游','原神','金铲铲之战','香肠派对','和平精英','崩坏：星穹铁','蛋仔派对','腾讯视频','爱奇艺','哔哩哔哩','抖音','快手','斗鱼','腾讯会议','百度贴吧','中国大学MOOC','作业帮','网易云音乐','淘宝','背景']
#王者荣耀,崩坏：星穹铁 ,原神 wzx  redmi
#原神,蛋仔派对 hmh
#和平精英,香肠派对 lmy  oneplus
#英雄联盟手游,崩坏：星穹铁 zz    sansaum


# # 10app
# target_applabel = {'爱奇艺': 0, '金铲铲之战': 1, '哔哩哔哩': 2, '中国大学MOOC': 3, '虎牙直播': 4, '百度贴吧': 5,
#                    'QQ音乐': 6}
# targetname = ['爱奇艺', '金铲铲之战', '哔哩哔哩', '中国大学MOOC', '虎牙直播', '百度贴吧','QQ音乐','Background']

# 23app`

# target_applabel = {'王者荣耀': 0, '爱奇艺': 1, 'QQ音乐': 2, '抖音': 3, '和平精英': 4, '金铲铲之战': 5, '哔哩哔哩': 6, '腾讯会议': 7, '中国大学MOOC': 8, '原神': 9, 'QQ飞车': 10, '网易会议': 11, '香肠派对': 12, '百度贴吧': 13, '虎牙直播': 14, '斗鱼': 15, '腾讯视频': 16, '火影忍者': 17, '知乎': 18, '蛋仔派对': 19, '微博': 20, '英雄联盟手游': 21}
# targetname = ['王者荣耀', '爱奇艺', 'QQ音乐', '抖音', '和平精英', '金铲铲之战', '哔哩哔哩', '腾讯会议', '中国大学MOOC', '原神', 'QQ飞车', '网易会议', '香肠派对', '百度贴吧', '虎牙直播', '斗鱼', '腾讯视频', '火影忍者', '知乎', '蛋仔派对', '微博', '英雄联盟手游', 'VR', '背景']

# 14app
# target_applabel = {'网易云音乐': 4, '百度贴吧': 0, '腾讯会议': 1, '淘宝': 5 ,'王者荣耀': 2, '腾讯视频': 3,'原神':6,
#                    '哔哩哔哩': 7, '金铲铲之战': 8, '爱奇艺': 9, '香肠派对': 10, '和平精英': 11}
# targetname = ['百度贴吧', '腾讯会议', '王者荣耀', '腾讯视频', '网易云音乐', '淘宝', '原神', '哔哩哔哩', '金铲铲之战', '爱奇艺', '香肠派对', '和平精英', '背景']


# 使用的model
# model = 'netsniff'
# model = 'AI'
# model = 'AI+dns'
# model = 'AI+tls'
model = 'AI+dns+tls'
# 置信度阈值
threshold = 0.99


if __name__ == '__main__':
    # pcapdroid文件目录
    pcappath = './apppcap/'
    # 预测结果+特征
    #pairfile = './raw.csv'
    predictionpath = './data/prediction.txt'
    # vrip = '192.168.2.5'
    mercury_path = 'bak/mercury.json'

    pcappathlist = walkFile(pcappath)

    # 真实流
    pcapcatch_flow = []
    # 预测流
    prediction_flow = []

    if 'tls' in model:
        get_mercury_key(pcappathlist, mercury_path)

    if 'dns' in model:
        for pcapfile in pcappathlist:
            ipdnsdirect(pcapfile)

    for pcapfile in pcappathlist:
        # 读取真实流pcap
        pcapcatch_flow += createfrompcap(pcapfile)


    # 读取预测流text
    #preprocesstext(pairfile, predictionpath)
    # prediction_flow = createfrompair(predictionpath)
    prediction_flow = createfromtext(predictionpath)

    print('pcapdroid抓取真实流数: ', len(pcapcatch_flow))
    print('预测流数: ', len(prediction_flow))

    # flag = False流记录数
    count = 0
    # 真实标签
    true_label = []
    # 预测标签
    predict_label = []
    # 低于阈值的流
    low_threshold = []
    # 阈值取值
    true_thresholds = []
    false_thresholds = []
    true_thresholds09 = []
    false_thresholds09 = []

    # 遍历pcapdroid真实流
    for pcf in pcapcatch_flow:
        # pcf = [五元组, 真实标签]
        # 遍历预测流
        for pf in prediction_flow:
            # pf = [五元组, 预测标签, 置信度]
            # 如果五元组匹配成功,则说明两个都有
            if pf[0] == pcf[0]:
                count += 1
                if pf[2] >= threshold:
                    true_label.append(pcf[1])
                    predict_label.append(pf[1])
                else:
                    # 低于阈值的流
                    low_threshold.append([pcf[0], str(pcf[1]), str(pf[1]), str(pf[2])])

                #  直方图的阈值参数
                if pf[2] >= 0.9:
                    if pf[1] == pcf[1]:
                        true_thresholds09.append(pf[2])
                    else:
                        false_thresholds09.append(pf[2])
                if pf[1] == pcf[1]:
                    true_thresholds.append(pf[2])
                else:
                    false_thresholds.append(pf[2])

    print('pcapdroid有,dpisniff没有的流记录数: ', len(pcapcatch_flow) - count)
    print('dpisniff有,pcapdroid没有的流记录数: ', len(prediction_flow) - count)

    # # 统计VR
    # vr_no = len(targetname) - 2
    # for pf in prediction_flow:
    #     if vrip in pf[0]:
    #         true_label.append(vr_no)
    #         predict_label.append(pf[1])
    #         if pf[2] >= 0.9 and pf[1] == vr_no:
    #             true_thresholds09.append(pf[2])
    #         elif pf[2] >= 0.9 and pf[1] != vr_no:
    #             false_thresholds09.append(pf[2])
    #         elif pf[1] == vr_no:
    #             true_thresholds.append(pf[2])
    #         elif pf[1] != vr_no:
    #             false_thresholds.append(pf[2])

    appflow_count = len(true_thresholds) + len(false_thresholds)


    print("true_label", set(true_label))
    print("predict_label", set(predict_label))
    # writelist(low_threshold, './output/low_threshold.csv')
    # print('正在写入文件：./output/low_threshold.csv')

    label_results = pd.DataFrame()
    label_results['true_label'] = true_label
    label_results['predict_label'] = predict_label
    label_results.to_csv('./output/label_results.csv', index=False)

    usedpredlabel=list(set(predict_label))
    usedname=[key for key,value in target_applabel_compare .items() if value in usedpredlabel]
    print('usedname:{}'.format(usedname))

    # 本地测试
    report = classification_report(true_label, predict_label)

    print(report)
    f = open('output/indicator_results.csv', mode='a')
    t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) + '\n'
    f.write(t)
    f.write(str(target_applabel) + '\n')
    f.write('描述：使用的模型是 ' + model +
            '; 置信度阈值是' + str(threshold) +
            '; pcapdroid抓取真实流数是 ' + str(len(pcapcatch_flow)) +
            '; 预测流数是 ' + str(len(prediction_flow)) +
            '; pcapdroid有，dpisniff没有的流记录数是 ' + str(count) + '\n')
    f.write(report)
    f.close()

    # 绘制阈值的直方图
    threshold09_hist(true_thresholds09, false_thresholds09)
    threshold_hist(true_thresholds, false_thresholds)
    # 绘制report结果直方图
    report_bar(report)
    # 绘制饼图
    report_pie(report, appflow_count)
    # 计算混淆矩阵

    cm = confusion_matrix(true_label, predict_label)
    # 每一类真实标签的总数
    class_totals = np.sum(cm, axis=1)
    cm_ratios = cm / class_totals[:, np.newaxis]
    ratios_confusion_matrix(cm_ratios, usedname)

    # # 输出正确识别率最高的流+特征
    # max_truepredict(cm_ratios, pcapcatch_flow, prediction_flow, usedname)
    # # 输出误识别率最高的流+特征
    # max_mispredict(cm_ratios, pcapcatch_flow, prediction_flow, usedname)


    # # flask后端数据
    # # classification report
    # report = classification_report(true_label, predict_label, target_names=targetname, output_dict=True)
    # report = pd.DataFrame(report).transpose()
    #
    # report_all = report.copy()
    # report_all.applymap(lambda x: np.ceil(x * 100) / 100)
    # precisions = report_all['precision'].values[0: -3]
    # recalls = report_all['recall'].values[0: -3]
    # f1_scores = report_all['f1-score'].values[0: -3]
    # report_dict = {'classes': targetname, 'precisions': precisions.tolist(), 'recalls': recalls.tolist(),
    #                'f1_scores': f1_scores.tolist()}
    #
    # with open('./output/report.json', 'w') as json_file:
    #     json.dump(report_dict, json_file)
    #
    # # confusion matrix
    # cm = confusion_matrix(true_label, predict_label)
    # class_totals = np.sum(cm, axis=1)
    # cm_ratios = cm / class_totals[:, np.newaxis]
    # cm_ratios = np.ceil(cm_ratios * 100) / 100
    # cm_xyv = []
    # rows, cols = np.indices(cm.shape)
    # for row, col in zip(rows.flatten(), cols.flatten()):
    #     cm_xyv.append([row.astype(np.float64), col.astype(np.float64), cm_ratios[row, col]])
    # cm_dict = {'confusion_matrix': cm_xyv, 'classname': targetname}
    #
    # with open('./output/confusion_matrix.json', 'w') as json_file:
    #     json.dump(cm_dict, json_file)
    #
    #
    # # accuracy pie
    # pie = report.copy()
    # pie['true_predict'] = pie['recall'] * pie['support']
    # pie['false_predict'] = pie['support'] - pie['true_predict']
    # all_acc = pie['support'].values[-3]
    # all_support = pie['support'].values[-1]
    # true_num = pie['true_predict'].values[0: -3]
    # true_num = np.append(true_num, (all_acc * all_support))
    # false_num = pie['false_predict'].values[0: -3]
    # false_num = np.append(false_num, (all_support - true_num[-1]))
    # targetname.append('总')
    # pie_dict = {'classes': targetname, 'true_predict': true_num.astype(int).tolist(),
    #             'false_predict': false_num.astype(int).tolist()}
    #
    # with open('./output/pie.json', 'w') as json_file:
    #     json.dump(pie_dict, json_file)