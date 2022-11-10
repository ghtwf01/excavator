import requests
from lib.core.common import similar, get_replaced_url, vuln_print
from urllib import parse
from lib.settings import jsonp_args, vuln_level

class Jsonp_Check:
    def check_jsonp(self, url, method, text1):
        dict = parse.parse_qs(parse.urlparse(url).query)
        for key, value in dict.items():
            if key in jsonp_args:
                url1 = get_replaced_url(url, dict[key][0], "aSdfGd")
                res = requests.get(url1).text
                if "aSdfGd" in res:
                    print("检测到jsonp接口，探测是否存在劫持风险")
                    headers = {"Referer":"https://www.test.com"}
                    text2 = requests.get(url, headers=headers).text
                    similar_rate = similar(text1, text2)
                    if similar_rate >= 0.9:
                        vuln_print(url, "jsonp", vuln_level["jsonp"], method)

