import os.path
from socket import *
import struct
import re
import pandas as pd

if os.path.exists('./output/monitor.csv'):
    os.remove('./output/monitor.csv')
sock = socket()
sock.bind(('', 8889))
sock.listen(1)
with sock:
    conn, addr = sock.accept()
    with conn:
        while True:
            head = conn.recv(4)
            if not head:
                break
            h = struct.unpack('>ccH', head)
            datalen = int(h[2])
            data = conn.recv(datalen)

            monitor_df = pd.DataFrame(
                columns=['cpu0', 'cpu1', 'cpu2', 'cpu3', 'MemAvailable', 'MemUsed', 'PredictCnt', 'Per_PredictCnt'])

            # 获取实时数据
            decoded_data = data.decode('utf-8')
            cpu_list = re.findall(r'cpu\d+ - load (\d+\.\d+)%', decoded_data)
            memory_list = re.findall(r': (\d+) kB', decoded_data)
            predictcnt = re.findall(r'PredictCnt: (\d+)', decoded_data)[0]

            # str转float
            cpu0, cpu1, cpu2, cpu3 = [float(x) for x in cpu_list]
            memory_available, memory_used = [float(x) for x in memory_list]
            predictcnt = float(predictcnt)

            # 计算瞬时流处理数
            if monitor_df.shape[0] == 0:
                per_predictcnt = predictcnt / 2
            else:
                per_predictcnt = (predictcnt - monitor_df['PredictCnt'].values[-1]) / 2

            # 数据存入dataframe
            monitor_df.loc[len(monitor_df)] = [cpu0, cpu1, cpu2, cpu3, memory_available, memory_used, predictcnt,
                                               per_predictcnt]
            # print(monitor_df)
            monitor_df.to_csv('./output/monitor.csv', index=False, header=False, mode='a')