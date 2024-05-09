# evaluation  
│  dnsprocess.py: 处理pcap包的DNS，提取每个DNS对应的域名  
│  fig_plot.py  
│  mercury  
│  mercury_process.py：使用mercury工具提取pcapdroid包中tls/http/https/dns对应的五元组
│  srv.py: 接收性能监控数据
│  step4 compare dpi.py:   
│  step4 compareV2.py：预测结果评估代码  
│  udp.py：接收预测结果  
└─ app.py：后端数据处理  

# extract  
│  csvdb.py  
│  options.py  
│  pktsextract.py：根据pcapdroid文件按照应用提纯镜像pcap文件  
│  pktsextract v2.py：将pcapdroid文件按照应用分别提纯  
│  step1 getfeature.py：启动特征提取模块的命令  
│  step2 csvextract.py：提取五元组+特征+应用名  
│  step3 writedb.py：提取结果存入数据库  
│  
├─pcapdroid  
├─extractpcap  
└─pcap  

# test_command：测试命令
