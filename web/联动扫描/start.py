import threading
import requests
import time
import os
import re
import sys

def xray(port):
    return 0

def head(ip):
    try:
        r = requests.get("http://"+ip)
        text = r.headers['server']
        print(text+":"+ip)
        html = r.text
        title = re.findall(r"<title>(.+)</title>",html)
        print(title)
        f = open ('url.txt','a+',encoding='utf-8')
        f.write("http://"+ip+"\n")
        f.close()
        
    except:
        #print('error:'+ip)
        return 0
        
        
    try:
        r = requests.get("https://"+ip)
        text = r.headers['server']
        print(text+":"+ip)
        html = r.text
        title = re.findall(r"<title>(.+)</title>",html)
        print(title)
        f = open ('url.txt','a+',encoding='utf-8')
        f.write("https://"+ip+"\n")
        f.close()
    except:
        #print('error:'+ip)
        return 0
        
    try:
        r = requests.get("http://"+ip+":8080")
        text = r.headers['server']
        print(text+":"+ip)
        html = r.text
        title = re.findall(r"<title>(.+)</title>",html)
        print(title)
        f = open ('url.txt','a+',encoding='utf-8')
        f.write("http://"+ip+":8080\n")
        f.close()
    except:
        #print('error:'+ip)
        return 0
        

ip = input("ip:192.168.1. ip:")
for i in range(1,255):
    tar = ip+str(i)
    thread = threading.Thread(target=head,args=([tar]))
    thread.start()
    tar = ip