import random
from urllib import parse
import platform
import os
import difflib


def random_str(nums):
    seed = "1234567890abcdefghijklmnopqrstuvwxyz"
    sa = []
    for i in range(nums):
        sa.append(random.choice(seed))
    salt = ''.join(sa)
    return salt

def banner():
    print(
        '''
        
███████╗██╗  ██╗ ██████╗ █████╗ ██╗   ██╗ █████╗ ████████╗ ██████╗ ██████╗ 
██╔════╝╚██╗██╔╝██╔════╝██╔══██╗██║   ██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
█████╗   ╚███╔╝ ██║     ███████║██║   ██║███████║   ██║   ██║   ██║██████╔╝
██╔══╝   ██╔██╗ ██║     ██╔══██║╚██╗ ██╔╝██╔══██║   ██║   ██║   ██║██╔══██╗
███████╗██╔╝ ██╗╚██████╗██║  ██║ ╚████╔╝ ██║  ██║   ██║   ╚██████╔╝██║  ██║
╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                                                                           
                                                             v1.0
        '''
    )
def random_num(nums):
    seed = "123456789"
    sa = []
    for i in range(nums):
        sa.append(random.choice(seed))
    salt = ''.join(sa)
    return int(salt)


def get_content_type(response):
    content_type = ""
    try:
        content_type = response.headers['Content-Type']
        content_type = response.headers['content-type']
    except:
        pass
    return content_type

def similar(text1, text2):
    return difflib.SequenceMatcher(None, text1, text2).quick_ratio()

def get_replaced_url(url, value, target_address, token=""):
    scheme = parse.urlparse(url).scheme
    netloc = parse.urlparse(url).netloc
    path = parse.urlparse(url).path
    query = parse.unquote(parse.urlparse(url).query)
    if token == "":
        query1 = query.replace(value, target_address)
    else:
        query1 = query.replace(value, target_address + token)
    url1 = scheme + "://" + netloc + path + "?" + query1
    return url1

def recharge_report():
    if os.path.exists("report/res.txt"):
        if platform.system().lower() == "windows":
            os.system("del report/res.txt")
        else:
            os.system("rm report/res.txt")

def vuln_print(url, vuln_type, level, method, body=""):
    msg = ""
    if method == "GET":
        msg = ('''
\033[31m
[vuln]
Method:%s
Url:%s
Vuln_type:%s
Level:%s
\033[0m
        ''') % (method, url, vuln_type, level)
    if method == "POST":
        msg = ('''
\033[31m
[vuln report]
Method:%s
Url:%s
Body:%s
Vuln_type:%s
Level:%s
\033[0m
        ''') % (method, url, str(body).strip(), vuln_type, level)
    print(msg.strip())
    with open("report/res.txt", "a") as file:
        file.write(msg.strip().strip("\033[0m").strip("\033[31m")+"\n")
