import json
import re
from urllib import parse
import requests
from lib.core.common import get_replaced_url, vuln_print
from lib.settings import file_read_args
from lib.settings import file_read_payloads
from lib.settings import file_read_regexArray
from lib.settings import vuln_level

class File_Read_Check:
    def check_get_file_read(self, request):
        url = request.url
        dict = parse.parse_qs(parse.urlparse(url).query)
        for key, value in dict.items():
            if (key.lower() in file_read_args) or ("." in value or "/" in value):
                for payload in file_read_payloads:
                    url1 = get_replaced_url(url, dict[key][0], payload)
                    html = requests.get(url1, headers=request.headers).text
                    for regx in file_read_regexArray:
                        if re.search(regx, html, re.I | re.S | re.M):
                            print("存在任意文件读取，payload："+url1)
                            vuln_print(url1, "file_read", vuln_level["file_read"], request.method)
                            break

    def check_post_urlencode_file_read(self, request):
        url = request.url
        body = request.get_text()
        mid_url = "https://www.baidu.com?" + body
        dict = parse.parse_qs(parse.urlparse(mid_url).query)
        for key, value in dict.items():
            if (key.lower() in file_read_args) or ("." in value or "/" in value):
                for payload in file_read_payloads:
                    dict[key][0] = payload
                    html = requests.post(url, data=dict, headers=request.headers).text
                    for regx in file_read_regexArray:
                        if re.search(regx, html, re.I | re.S | re.M):
                            print("存在任意文件读取，url："+url+", body："+str(dict))
                            vuln_print(url, "file_read", vuln_level["file_read"], request.method, str(dict))
                            break

    def check_post_json_file_read(self, request):
        url = request.url
        body = request.get_text()
        dict = json.loads(body)
        for key, value in dict.items():
            if type(value).__name__ == "str":
                for payload in file_read_payloads:
                    dict[key] = payload
                    html = requests.post(url, data=json.dumps(dict), headers=request.headers).text
                    for regx in file_read_regexArray:
                        if re.search(regx, html, re.I | re.S | re.M):
                            print("存在任意文件读取，url："+url+", body："+str(dict))
                            vuln_print(url, "file_read", vuln_level["file_read"], request.method, str(dict))
                            break