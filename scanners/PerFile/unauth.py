import json

import requests
from lib.core.common import similar, vuln_print
from lib.settings import vuln_level
from urllib import parse


class UnAuthCheck:
    @staticmethod
    def check_get_unauth(url, req_headers, method, response_text):
        for key, value in req_headers.items():
            if key.lower() in ["cookie", "token", "auth"]:
                req_headers[key] = ""
                html = ""
                try:
                    html = requests.get(url, headers=req_headers, allow_redirects=False).text
                except BaseException:
                    pass
                if similar(html, response_text) >= 0.95:
                    print(url + " 存在未授权访问")
                    vuln_print(url, "unauth", vuln_level["unauth"], method)

    @staticmethod
    def check_post_urlencode_unauth(
            url,
            req_headers,
            method,
            body,
            response_text):
        mid_url = "https://www.baidu.com?" + body
        dict = parse.parse_qs(parse.urlparse(mid_url).query)
        for key, value in req_headers.items():
            if key.lower() in ["cookie", "token", "auth"]:
                req_headers[key] = ""
                html = ""
                try:
                    html = requests.post(url, data=dict, headers=req_headers, allow_redirects=False).text
                except BaseException:
                    pass
                if similar(html, response_text) >= 0.95:
                    print(url + " 存在未授权访问")
                    vuln_print(
                        url,
                        "unauth",
                        vuln_level["unauth"],
                        method,
                        body)

    @staticmethod
    def check_post_json_unauth(
            url,
            req_headers,
            method,
            body,
            response_text):
        dict = json.loads(body)
        for key, value in req_headers.items():
            if key.lower() in ["cookie", "token", "auth"]:
                req_headers[key] = ""
                html = ""
                try:
                    html = requests.post(url, data=dict, headers=req_headers, allow_redirects=False).text
                except BaseException:
                    pass
                if similar(html, response_text) >= 0.95:
                    print(url + " 存在未授权访问")
                    vuln_print(
                        url,
                        "unauth",
                        vuln_level["unauth"],
                        method,
                        body)
