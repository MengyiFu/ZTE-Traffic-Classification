"""
@Time    : 2022/7/4 16:09
-------------------------------------------------
@Author  : sailorlee(lizeyi)
@email   : sailorlee31@gmail.com
-------------------------------------------------
@FileName: csvdb.py
@Software: PyCharm
"""
#from sshtunnel import SSHTunnelForwarder
import pymysql
import pandas as pd
import numpy as np
columsname=['payloadSum','s_fHeaderBytes','s_bHeaderBytes','s_fPktsCounts','s_bPktsCounts','s_fPktsPerSecond','s_bPktsPerSecond','s_lenMin','s_lenMax','s_lenMean','s_lenVar','s_lenSd','s_fin','s_syn','s_rst','s_psh','s_ack','s_urg','s_cwr','s_ece','s_fTcpWindown','s_bTcpWindown','s_PktsPerSecond','s_fPayloadSum','s_bPayloadSum','s_fLenMin','s_fLenMax','s_fLenMean','s_fLenSd','s_fLenVar','s_bLenMin','s_bLenMax','s_bLenMean','s_bLenSd','s_bLenVar','s_bytesPerSecond','s_downUpRatio','s_flowIATMean','s_flowIATMin','s_flowIATMax','s_flowIATTotal','s_fIATMean','s_fIATMin','s_fIATMax','s_fIATTotal','s_fIATSd','s_fIATVar','s_bIATMean','s_bIATMin','s_bIATMax','s_bIATTotal','s_bIATSd','s_bIATVar','s_flowIATSd','s_flowIATVar','s_subflowCnt','s_duration','s_subflowForwardBytes','s_subflowBackwardBytes','s_subflowForwardPkts','s_subflowBackwardPkts','s_fwdSegSizeAvg','s_bwdSegSizeAvg','s_activeMin','s_activeMax','s_activeMean','s_activeSum','s_activeVar','s_activeSd','s_activeCnt','s_idleMin','s_idleMax','s_idleMean','s_idleSum','s_idleVar','s_idleSd','s_idleCnt','s_fBulkStateCount','s_fBulkPacketCount','s_fBulkSizeTotal','s_fBulkDuration','s_bBulkStateCount','s_bBulkPacketCount','s_bBulkSizeTotal','s_bBulkDuration','s_fAvgBytesPerBulk','s_fAvgPacketsPerBulk','s_fAvgBulkRate','s_bAvgBytesPerBulk','s_bAvgPacketsPerBulk','s_bAvgBulkRate','s_avgPktSize','s_fActDataPkts','s_fMinSegSize','s_fPSHCnt','s_bPSHCnt','s_fURGCnt','s_bURGCnt','proto']
#columsname=['ip1','ip2','port1','port2','proto','payloadSum','s_fHeaderBytes','s_bHeaderBytes','s_fPktsCounts','s_bPktsCounts','s_fPktsPerSecond','s_bPktsPerSecond','s_lenMin','s_lenMax','s_lenMean','s_lenVar','s_lenSd','s_fin','s_syn','s_rst','s_psh','s_ack','s_urg','s_cwr','s_ece','s_fTcpWindown','s_bTcpWindown','s_PktsPerSecond','s_fPayloadSum','s_bPayloadSum','s_fLenMin','s_fLenMax','s_fLenMean','s_fLenSd','s_fLenVar','s_bLenMin','s_bLenMax','s_bLenMean','s_bLenSd','s_bLenVar','s_bytesPerSecond','s_downUpRatio','s_flowIATMean','s_flowIATMin','s_flowIATMax','s_flowIATTotal','s_fIATMean','s_fIATMin','s_fIATMax','s_fIATTotal','s_fIATSd','s_fIATVar','s_bIATMean','s_bIATMin','s_bIATMax','s_bIATTotal','s_bIATSd','s_bIATVar','s_flowIATSd','s_flowIATVar','s_subflowCnt','s_duration','s_subflowForwardBytes','s_subflowBackwardBytes','s_subflowForwardPkts','s_subflowBackwardPkts','s_fwdSegSizeAvg','s_bwdSegSizeAvg','s_activeMin','s_activeMax','s_activeMean','s_activeSum','s_activeVar','s_activeSd','s_activeCnt','s_idleMin','s_idleMax','s_idleMean','s_idleSum','s_idleVar','s_idleSd','s_idleCnt','s_fBulkStateCount','s_fBulkPacketCount','s_fBulkSizeTotal','s_fBulkDuration','s_bBulkStateCount','s_bBulkPacketCount','s_bBulkSizeTotal','s_bBulkDuration','s_fAvgBytesPerBulk','s_fAvgPacketsPerBulk','s_fAvgBulkRate','s_bAvgBytesPerBulk','s_bAvgPacketsPerBulk','s_bAvgBulkRate','s_avgPktSize','s_fActDataPkts','s_fMinSegSize','s_fPSHCnt','s_bPSHCnt','s_fURGCnt','s_bURGCnt','proto']
#columsname=['ip1','ip2','port1','port2','proto','startSec','startNSec','endSec','endNSec','FlowDuration','TotCntFwdPkts','TotCntBwdPkts','TotLenFwdBytes','TotLenBwdBytes','Packet Length Min','Packet Length Max','Packet Length Mean','Packet Length Variance','Packet Length Std','fLenMin','fLenMax','fLenMean','fLenVar','fLenSd','bLenMin','bLenMax','bLenMean','bLenVar','bLenSd','Flow Bytes/s','Flow Packets/s','Flow IAT Mean','Flow IAT Std','Flow IAT Max','Flow IAT Min','Flow IAT Total','Flow IAT Var','Fwd IAT Min','Fwd IAT Max','Fwd IAT Mean','Fwd IAT Std','Fwd IAT Total','Fwd IAT Var','Bwd IAT Min','Bwd IAT Max','Bwd IAT Mean','Bwd IAT Std','Bwd IAT Total','Bwd IAT Var','Fwd PSH flags','Bwd PSH Flags','Fwd URG Flags','Bwd URG Flags','Fwd Header Length','Bwd Header Length','FWD Packets/s','Bwd Packets/s','fin','syn','rst','psh','ack','urg','cwr','ece','fTcpWindow','bTcpWindow','down/Up Ratio','Average Packet Size','Fwd Segment Size Avg','Bwd Segment Size Avg','Fwd Bytes/Bulk Avg','Fwd  Packet/Bulk Avg','Fwd Bulk Rate Avg','Bwd Bytes/Bulk Avg','Bwd Packet/Bulk Avg','Bwd Bulk Rate Avg','Subflow Fwd Packets','Subflow Fwd Bytes','Subflow Bwd Packets','Subflow Bwd Bytes','Fwd Act Data Pkts','Fwd Seg Size Min','Active Min','Active Mean','Active Max','Active Std','Idle Min','Idle Mean','Idle Max','Idle Std']
class ConnectMysql:
    def __init__(self, opt):
        self.opt = opt
        # self.server = SSHTunnelForwarder(
        #     ssh_address_or_host=(self.opt.server_ip, self.opt.server_port),
        #     ssh_username=self.opt.server_username,
        #     ssh_password=self.opt.server_password,
        #     remote_bind_address=(self.opt.mysql_ip,self.opt.mysql_port)
        # )
        # self.server.start()
        self.connect = pymysql.connect(
            host=self.opt.mysql_ip,
            port=self.opt.mysql_port,
            user=self.opt.mysql_username,
            passwd=self.opt.mysql_password,
            db=self.opt.databaseName,
            charset='utf8'
        )
        self.cursor = self.connect.cursor()


    # def __del__(self):
    #     #self.cursor.close()
    #     #self.connect.close()
    #     #self.server.close()
    #     #print('close success!')

    def read_csv_columns(self,filepath):
        # todo 这里对接王梓炫组，读取数据的代码仅供算法组测试，
        #  这里面需要传递的一个dataframe格式的数据
        csv_name = filepath
        data = pd.read_csv(csv_name, encoding='gb2312')
        # 这里不变
        #columns = data.columns.tolist()
        columns=columsname
        return columns

    def read_csv_values(self,filepath):

        # todo 这里对接王梓炫组，读取数据的代码仅供算法组测试，
        #  这里面需要传递的一个dataframe格式的数据
        csv_name=filepath
        data = pd.read_csv(csv_name, encoding='gb2312',header=None)
        #这里不需要变化
        print('the shape of data we get.',data.shape)

        data = pd.DataFrame(data)
        #data_3 = list(data.values)

        return data

    def write_mysql(self,data):
        for i in data:
            data_6 = tuple(i)
            sql = 'insert into {} values{}'.format(self.opt.tableName, data_6)
            #print(sql)
            self.cursor.execute(sql)
            self.commit()
        print("\nComplete write data operation!")

    def commit(self):
        # 定义一个确认事务运行
        self.connect.commit()

    def create(self,data):
        #print(text)
        columns = data.columns.tolist()
        types = data.dtypes
        make_table = []
        for item in columns:
           if 'int' in str(types[item]):
               item = str(item)
               item = item.replace(" ", "_")
               item = item.replace("/", "_")
               item = item.replace(".", "_")
               char = item + ' INT'
           elif 'float' in str(types[item]):
               item = str(item)
               item = item.replace(" ", "_")
               item = item.replace("/", "_")
               item = item.replace(".", "_")
               char = item + ' FLOAT'
           elif 'object' in str(types[item]):
               item = str(item)
               item = item.replace(" ", "_")
               item = item.replace("/", "_")
               item = item.replace(".", "_")
               char = item + ' VARCHAR(255)'
           elif 'datetime' in str(types[item]):
               item = str(item)
               item = item.replace(" ", "_")
               item = item.replace("/", "_")
               item = item.replace(".", "_")
               char = item + ' DATETIME'
           make_table.append(char)
        columns=','.join(make_table)
        sql='CREATE TABLE {}({})'.format(self.opt.tableName, columns)
        print("sql",sql)
        self.cursor.execute('CREATE TABLE {}({})'.format(self.opt.tableName, columns))
        self.commit()

    def exists(self):
        sql = "SHOW TABLES LIKE '{}' ".format(self.opt.tableName)
        self.cursor.execute(sql)
        result = self.cursor.fetchall()
        return len(result) != 0

    def start_write_csv(self):
        '''
        yang write
        :return:none
        '''

        if ~self.exists():
            self.create()
        self.write_mysql()

    def read_data_from_mysql(self,time):
        '''
        time: the number of data we get
        get data from mysql
        :return:
        '''

        sql = 'SELECT * FROM {}'.format(self.opt.tableName)
        self.cursor.execute(sql)
        data_dict = []
        for field in self.cursor.description:
            data_dict.append(field[0])
        data = self.cursor.fetchall()
        df = pd.DataFrame(list(data))
        df.columns = data_dict

        return df.head(time)