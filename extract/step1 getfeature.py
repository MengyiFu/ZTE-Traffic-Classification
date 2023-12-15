import subprocess
import os, signal
import time
import multiprocessing


flowresultpath = '/home/fmy/文档/2023中兴-流量分类/extractinput/raspberrypi_csv/'
njuptpath = '/home/fmy/文档/2023中兴-流量分类/ksniffer/embedai-int/'


if __name__ == '__main__':

    # appname = '王者荣耀'
    # appver = 'v8.3.1.9'
    appname = '抖音'
    appver = 'v24.9.0'

    paltform = 'Android'
    chargeperson = 'fmy'
    localtime = time.strftime('%Y%m%d%H%M%S', time.localtime())
    csvfilename = appname + '_' + appver + '_' + paltform + '_' + localtime + '_' + chargeperson + '.csv'
    print('csvfilename', csvfilename)
    resultfilepath = flowresultpath + csvfilename
    print('resultfilepath', resultfilepath)


    # 启动njupt
    njuptcmd = ' cd %s && exec ./njupt -P -n -t -D >> %s ' % (njuptpath, resultfilepath)
    njupt = subprocess.Popen(njuptcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
    print("njupt.pid", njupt.pid)


    # 卸载模块
    rmcmd = 'echo %s | sudo -S rmmod /home/fmy/文档/2023中兴-流量分类/ksniffer/src/netsniff.ko' % '123123'
    rmcapsniff = subprocess.Popen(rmcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
    rmcapsniff.wait()
    print("rmcapsniff.stdout", rmcapsniff.stdout.readlines())
    print("rmcapsniff.stderr", rmcapsniff.stderr.readlines())

    # 启动模块
    insmd = 'echo %s | sudo -S insmod /home/fmy/文档/2023中兴-流量分类/ksniffer/src/netsniff.ko' % '123123'
    inscapsniff = subprocess.Popen(insmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
    inscapsniff.wait()
    print("inscapsniff.stdout", inscapsniff.stdout.readlines())
    print("inscapsniff.stderr", inscapsniff.stderr.readlines())

    # 检测模块是否运行完毕
    njupt.send_signal(signal.SIGINT)
    njupt.wait()
