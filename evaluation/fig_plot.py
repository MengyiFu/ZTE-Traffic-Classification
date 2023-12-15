import time
import numpy as np
import seaborn as sns
from matplotlib import pyplot as plt


def threshold09_hist(true_thresholds, false_thresholds):
    plt.figure()
    plt.hist([true_thresholds, false_thresholds], bins=10, label=['predict_true', 'predict_false'])
    plt.xlabel('Threshold')
    plt.ylabel('Frequency')
    plt.title('Threshold Distribution Histogram')
    plt.xticks(np.arange(0.9, 1.01, 0.01))
    plt.legend()
    # plt.show()
    plt.savefig('./picture/0.9-1_histogram.png')


def threshold_hist(true_thresholds, false_thresholds):
    plt.figure()
    plt.hist([true_thresholds, false_thresholds], bins=10, label=['predict_true', 'predict_false'])
    plt.xlabel('Threshold')
    plt.ylabel('Frequency')
    plt.title('Threshold Distribution Histogram')
    plt.legend()
    # plt.show()
    plt.savefig('./picture/0-1_histogram.png')


def ratios_confusion_matrix(cm_ratios, classes):
    plt.figure(figsize=(24, 24))
    # 绘制混淆矩阵热力图
    sns.heatmap(cm_ratios, annot=True, cmap='Greens', fmt='.2f', square=True, xticklabels=True, yticklabels=True)
    plt.title('Confusion Matrix')
    # 设置中文字体
    plt.rcParams['font.sans-serif'] = 'simhei'
    # 设置刻度标签
    tick_marks = np.arange(len(classes)) + 0.5
    plt.xticks(tick_marks, classes, fontsize=18, rotation=15)
    plt.yticks(tick_marks, classes, fontsize=18, rotation=15)
    # 设置轴标签
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    # plt.show()
    plt.savefig('./picture/confusion_matrix.png')

def writelist(li, listpath):
    f = open(listpath, mode='a')
    for l in li:
        if not isinstance(l, str):
            l = ','.join(l)
        f.write(l)
    f.close()

def max_mispredict(cm, pcapcatch_flow, prediction_flow, targetname):
    np.fill_diagonal(cm, 0)
    index = np.unravel_index(np.argmax(cm), cm.shape)
    # 输出误识别率最高的流+特征
    mc_true = index[0]
    mc_pred = index[1]
    max_confusion = []
    mc_pred_feature = []
    mc_true_feature = []
    for pcf in pcapcatch_flow:
        # pcf = [五元组, 真实标签]
        # 遍历预测流
        for pf in prediction_flow:
            # pf = [五元组, 预测标签, 置信度, 特征]
            if pf[0] == pcf[0] and pf[1] == mc_pred and pcf[1] == mc_true:
                max_confusion.append([pf[3]])
            if pf[0] == pcf[0] and pf[1] == mc_pred and pcf[1] == mc_pred:
                mc_pred_feature.append([pf[3]])
            if pf[0] == pcf[0] and pf[1] == mc_true and pcf[1] == mc_true:
                mc_true_feature.append([pf[3]])

    localtime = time.strftime('%Y%m%d%H%M%S', time.localtime())
    mc_fpath = './output/' + targetname[mc_true] + '误识别为' + targetname[mc_pred] + '_' + localtime + '.csv'
    mc_pred_fpath = './output/' + targetname[mc_pred] + '_' + localtime + '.csv'
    mc_true_fpath = './output/' + targetname[mc_true] + '_' + localtime + '.csv'
    writelist(max_confusion, mc_fpath)
    print('正在写入文件：', mc_fpath)
    writelist(mc_pred_feature, mc_pred_fpath)
    print('正在写入文件：', mc_pred_fpath)
    writelist(mc_true_feature, mc_true_fpath)
    print('正在写入文件：', mc_true_fpath)


def max_truepredict(cm, pcapcatch_flow, prediction_flow, targetname):
    index = np.unravel_index(np.argmax(cm), cm.shape)
    mc_true = index[0]
    mc_pred = index[1]
    max_confusion = []
    for pcf in pcapcatch_flow:
        # pcf = [五元组, 真实标签]
        # 遍历预测流
        for pf in prediction_flow:
            # pf = [五元组, 预测标签, 置信度, 特征]
            if pf[0] == pcf[0] and pf[1] == mc_pred and pcf[1] == mc_true:
                max_confusion.append([pf[3]])
    localtime = time.strftime('%Y%m%d%H%M%S', time.localtime())
    mc_fpath = './output/' + targetname[mc_pred] + '_正确识别率最高_' + localtime + '.csv'
    writelist(max_confusion, mc_fpath)
    print('正在写入文件：', mc_fpath)


def readreport(report):
    labels = []
    precisions = []
    recalls = []
    f1_scores = []
    lines = report.split('\n')
    for line in lines[2: (len(lines) - 5)]:
        line = line.split()
        labels.append(line[0])
        precisions.append(float(line[1]))
        recalls.append(float(line[2]))
        f1_scores.append(float(line[3]))
    accuracy, support = lines[-4].strip().split()[1:]
    return labels, precisions, recalls, f1_scores, float(accuracy), int(support)


def report_bar(report):
    # report结果
    # labels = report.index[0: -3]
    # precisions = report['precision'].values[0: -3]
    # recalls = report['recall'].values[0: -3]
    # f1_scores = report['f1-score'].values[0: -3]
    labels, precisions, recalls, f1_scores = readreport(report)[0: 4]
    plt.figure(figsize=(16, 8))
    # 设置柱子的宽度
    bar_width = 0.25
    # 设置柱子的位置
    bar_position1 = np.arange(len(labels))
    bar_position2 = [x + bar_width for x in bar_position1]
    bar_position3 = [x + 2 * bar_width for x in bar_position1]
    # 绘制柱状图
    plt.bar(bar_position1, precisions, width=bar_width, label='precision')
    plt.bar(bar_position2, recalls, width=bar_width, label='recall')
    plt.bar(bar_position3, f1_scores, width=bar_width, label='f1_score')
    # 设置中文字体
    plt.rcParams['font.sans-serif'] = 'simhei'
    # 设置横纵轴标签
    plt.title('Classification Report Histogram')
    plt.xticks(bar_position2, labels, fontsize=13, rotation=15)
    plt.yticks(np.arange(0, 1.1, 0.1), fontsize=13)
    # 显示图例
    plt.legend()
    # plt.show()
    plt.savefig('./picture/report_bar.png')


def report_pie(report, all):
    # accuracy = report.loc['accuracy'].values[0]
    # support = report['support'].values[-1]
    accuracy, support = readreport(report)[-2:]
    labels = ['>threshold and True', '>threshold and False', '<threshold']
    true_count = round(support * accuracy)
    false_count = support - true_count
    sizes = [true_count, false_count, (all - support)]
    explode = (0, 0, 0)
    plt.figure()
    plt.pie(sizes, explode=explode, labels=labels, autopct='%1.1f%%')
    # plt.show()
    plt.savefig('./picture/report_piechart.png')