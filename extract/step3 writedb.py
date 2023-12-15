from options import Options
import csvdb
import os
from os import path
import pandas as pd
from sqlalchemy import create_engine
import numpy as np

def engine(dialect,driver,username,password,host,port,database):
    text=dialect+'+'+driver+'://'+username+':'+password+'@'+host+":"+port+"/"+database+"?charset=utf8"
    #engine = create_engine(text, encoding='utf-8')
    engine = create_engine(text,)
    return engine

filecolumns=['payloadSum','s_fHeaderBytes','s_bHeaderBytes','s_fPktsCounts','s_bPktsCounts','s_fPktsPerSecond','s_bPktsPerSecond','s_lenMin','s_lenMax','s_lenMean','s_lenVar','s_lenSd','s_fin','s_syn','s_rst','s_psh','s_ack','s_urg','s_cwr','s_ece','s_fTcpWindown','s_bTcpWindown','s_PktsPerSecond','s_fPayloadSum','s_bPayloadSum','s_fLenMin','s_fLenMax','s_fLenMean','s_fLenSd','s_fLenVar','s_bLenMin','s_bLenMax','s_bLenMean','s_bLenSd','s_bLenVar','s_bytesPerSecond','s_downUpRatio','s_flowIATMean','s_flowIATMin','s_flowIATMax','s_flowIATTotal','s_fIATMean','s_fIATMin','s_fIATMax','s_fIATTotal','s_fIATSd','s_fIATVar','s_bIATMean','s_bIATMin','s_bIATMax','s_bIATTotal','s_bIATSd','s_bIATVar','s_flowIATSd','s_flowIATVar','s_subflowCnt','s_duration','s_subflowForwardBytes','s_subflowBackwardBytes','s_subflowForwardPkts','s_subflowBackwardPkts','s_fwdSegSizeAvg','s_bwdSegSizeAvg','s_activeMin','s_activeMax','s_activeMean','s_activeSum','s_activeVar','s_activeSd','s_activeCnt','s_idleMin','s_idleMax','s_idleMean','s_idleSum','s_idleVar','s_idleSd','s_idleCnt','s_fBulkStateCount','s_fBulkPacketCount','s_fBulkSizeTotal','s_fBulkDuration','s_bBulkStateCount','s_bBulkPacketCount','s_bBulkSizeTotal','s_bBulkDuration','s_fAvgBytesPerBulk','s_fAvgPacketsPerBulk','s_fAvgBulkRate','s_bAvgBytesPerBulk','s_bAvgPacketsPerBulk','s_bAvgBulkRate','s_avgPktSize','s_fActDataPkts','s_fMinSegSize','s_fPSHCnt','s_bPSHCnt','s_fURGCnt','s_bURGCnt','proto']
#filecolumns=['s_lenMax','s_fLenMax','s_fTcpWindown','s_fLenSd','s_lenMean','s_fLenMean','s_lenSd','s_fwdSegSizeAvg','s_avgPktSize','s_fHeaderBytes','s_flowIATMax',
# 's_flowIATTotal','s_fIATMax','s_duration','s_fIATTotal','s_fIATMean','s_flowIATSd','s_fIATSd','s_fAvgBytesPerBulk','s_fBulkSizeTotal','s_fBulkPacketCount','s_flowIATMin',
# 's_fin','s_fIATMin','s_subflowForwardBytes','s_syn','s_fAvgPacketsPerBulk','s_idleMax','s_subflowForwardPkts','s_idleMean','s_idleMin','s_idleSum','s_fBulkStateCount',
# 's_subflowCnt','s_activeMin','s_activeSum','s_activeMean','s_rst','s_activeMax','s_idleCnt','s_activeCnt','s_idleSd','s_activeSd','s_fAvgBulkRate','s_bAvgBytesPerBulk',
# 's_bAvgBulkRate','s_bPSHCnt','s_bBulkDuration','s_fURGCnt']

#table_name = 'flowfeature_test'
#创建csv文件

def readFile_to_sql(data,table_name):
    try:
        #获取当前路径

        #直接写入数据库,'table_name'为表名,会自动创建一个表,不需要自己动手创建
        #to_sql函数支持两类mysql引擎一个是sqlalchemy，另一个是sqlliet3,在写入库
        # 的时候，pymysql(python3),mysqldb(python2)是不能用的，只能使用
        # sqlalchemy或者sqlliet3.
        data.to_sql(table_name,con=engine('mysql','pymysql','runtrend','4rfv*UHB','sh-cynosdbmysql-grp-5dmxbh9a.sql.tencentcdb.com','26618','flowfeature'),if_exists='append',index=True)
        #第一个参数't_pandasRead'是需要导入的表名
        #第二个参数数据库引擎
        #第三个参数if_exists=""，引号里面可以跟三个参数，fail（如果表存在，啥也不做），replace（如果表存在，删了表，再建立一个新表，把数据插入），append（如果表存在，把数据插入，如果表不存在创建一个表）
        #第四个参数是否需要配置索引
    except Exception as e:
        #输出报错问题
        raise e

#定义一个函数
def scaner_file (url):
    filepath_list=[]
    #遍历当前路径下所有文件
    file  = os.listdir(url)
    for f in file:
        #字符串拼接
        real_url = path.join (url , f)
        filepath_list.append(real_url)
        #打印出来
    return filepath_list

if __name__ == '__main__':
    filepath_list=scaner_file('./extractcsv/')
    # #step1读取参数
    opt = Options().parse()
    # #step2 创建连接mysql的类并连接数据库
    ConnectMysql=csvdb.ConnectMysql(opt)
    #step3 读取要插入的文件
    for filepath in filepath_list:
        #先获取辅助信息
        appname=filepath.split("_")[0].split("/")[-1]
        pcaptype=filepath.split("_")[1]
        appversion=filepath.split("_")[2]
        appplatform=filepath.split("_")[3]
        date=filepath.split("_")[4]
        chargeperson=filepath.split("_")[5].split(".")[0]
        print(appname)
        #读数据
        filedata = pd.read_csv(filepath, encoding='gb2312',header=None)
        filedata.columns=filecolumns
        filedata.dropna(inplace=True)
        Auxiliarylabel={"appname":[appname for i in range(filedata.shape[0])],"pcaptype":[pcaptype for i in range(filedata.shape[0])],"appversion":[appversion for i in range(filedata.shape[0])],"appplatform":[appplatform for i in range(filedata.shape[0])],"date":[date for i in range(filedata.shape[0])],"chargeperson":[chargeperson for i in range(filedata.shape[0])],"apptype":['' for i in range(filedata.shape[0])]}
        Auxiliarylabeldata=pd.DataFrame(Auxiliarylabel)
        data= pd.concat([filedata, Auxiliarylabeldata], axis=1)
        print("data",data.shape)
        # print("data",data)
        #直接一起插入
        #readFile_to_sql(data,'ZTE_AP_flowfeature_accuratelabel_sniffer_repaired')
        readFile_to_sql(data, 'ZTE_AP_flowfeature_accuratelabel_sniffer')
        #readFile_to_sql(data, 'RaspberryPi_flowfeature_accuratelabel_netniffer_new')