import json
import re

import numpy as np
import pandas as pd
from flask import Flask, jsonify, Response
from flask_cors import CORS
from PIL import Image
from io import BytesIO
import base64
from socket import *
import struct

from sklearn.metrics import classification_report, confusion_matrix, accuracy_score


app = Flask(__name__)
CORS(app, resources=r'/*')  # 允许来自特定源的跨域请求


def statistic(key, monitor, monitor_df):
    monitor[key]['current'] = monitor_df[key].values[-1]
    monitor[key]['min'] = round(monitor_df[key].min(), 2)
    monitor[key]['max'] = round(monitor_df[key].max(), 2)
    monitor[key]['ave'] = round(monitor_df[key].mean(), 2)


@app.route('/get_monitor_data', methods=['POST'])
def get_monitor_data():
    columns = ['cpu0', 'cpu1', 'cpu2', 'cpu3', 'MemAvailable', 'MemUsed', 'PredictCnt', 'Per_PredictCnt']
    monitor_df = pd.read_csv('./output/monitor.csv')
    monitor_df.columns = columns

    monitor = {'cpu0': {'current': 0.00, 'min': 0.00, 'max': 0.00, 'ave': 0.00},
               'cpu1': {'current': 0.00, 'min': 0.00, 'max': 0.00, 'ave': 0.00},
               'cpu2': {'current': 0.00, 'min': 0.00, 'max': 0.00, 'ave': 0.00},
               'cpu3': {'current': 0.00, 'min': 0.00, 'max': 0.00, 'ave': 0.00},
               'MemAvailable': {'current': 0.00, 'min': 0.00, 'max': 0.00, 'ave': 0.00},
               'MemUsed': {'current': 0.00, 'min': 0.00, 'max': 0.00, 'ave': 0.00},
               'Per_PredictCnt': {'current': 0.00, 'min': 0.00, 'max': 0.00, 'ave': 0.00}}

    # 统计数据min,max,ave
    for key in monitor.keys():
        statistic(key, monitor, monitor_df)
    return jsonify(monitor)


@app.route('/get_classification_report', methods=['POST'])
def get_report():
    try:
        # # classname = targetname.copy()
        # classname = ['原神', '王者荣耀', '和平精英', '背景']
        # label = pd.read_csv('./output/label_results.csv')
        # truelabel = label['true_label'].values
        # predictlabel = label['predict_label'].values
        # report = classification_report(truelabel, predictlabel, target_names=classname, output_dict=True)
        # report = pd.DataFrame(report).transpose()
        # report = report.applymap(lambda x: np.ceil(x * 100) / 100)
        # precisions = report['precision'].values[0: -3]
        # recalls = report['recall'].values[0: -3]
        # f1_scores = report['f1-score'].values[0: -3]
        # report_dict = {'classes': classname, 'precisions': precisions.tolist(), 'recalls': recalls.tolist(), 'f1_scores': f1_scores.tolist()}
        # return jsonify(report_dict)
        file_name = './output/report.json'
        with open(file_name, 'r') as json_file:
            report = json.load(json_file)
        return jsonify(report)
    except Exception as e:
        return jsonify({'get_classification_report': str(e)})


@app.route('/get_confusion_matrix', methods=['POST'])
def get_cm():
    try:
        # # classname = targetname.copy()
        # classname = ['原神', '王者荣耀', '和平精英', '背景']
        # label = pd.read_csv('./output/label_results.csv')
        # truelabel = label['true_label'].values
        # predictlabel = label['predict_label'].values
        # cm = confusion_matrix(truelabel, predictlabel)
        # class_totals = np.sum(cm, axis=1)
        # cm_ratios = cm / class_totals[:, np.newaxis]
        # cm_ratios = np.ceil(cm_ratios * 100) / 100
        # cm_xyv = []
        # rows, cols = np.indices(cm.shape)
        # for row, col in zip(rows.flatten(), cols.flatten()):
        #     cm_xyv.append([row.astype(np.float64), col.astype(np.float64), cm_ratios[row, col]])
        # cm_dict = {'confusion_matrix': cm_xyv, 'classname': classname}
        # return jsonify(cm_dict)
        file_name = './output/confusion_matrix.json'
        with open(file_name, 'r') as json_file:
            cm = json.load(json_file)
        return jsonify(cm)
    except Exception as e:
        return jsonify({'get_confusion_matrix error': str(e)})


@app.route('/get_pie_data', methods=['POST'])
def get_pie():
    try:
        # # classname = targetname.copy()
        # classname = ['原神', '王者荣耀', '和平精英', '背景']
        # label = pd.read_csv('./output/label_results.csv')
        # truelabel = label['true_label'].values
        # predictlabel = label['predict_label'].values
        # report = classification_report(truelabel, predictlabel, target_names=classname, output_dict=True)
        # report = pd.DataFrame(report).transpose()
        # report['true_predict'] = report['recall'] * report['support']
        # report['false_predict'] = report['support'] - report['true_predict']
        # all_acc = report['support'].values[-3]
        # all_support = report['support'].values[-1]
        # true_num = report['true_predict'].values[0: -3]
        # true_num = np.append(true_num, (all_acc * all_support))
        # false_num = report['false_predict'].values[0: -3]
        # false_num = np.append(false_num, (all_support - true_num[-1]))
        # classname.append('总')
        # pie_dict = {'classes': classname, 'true_predict': true_num.astype(int).tolist(),
        #             'false_predict': false_num.astype(int).tolist()}
        # return jsonify(pie_dict)
        file_name = './output/pie.json'
        with open(file_name, 'r') as json_file:
            pie = json.load(json_file)
        return jsonify(pie)
    except Exception as e:
        return jsonify({'get_pie_data error': str(e)})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
