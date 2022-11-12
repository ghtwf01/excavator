from urllib import parse
from lib.core.common import random_str, get_replaced_url, vuln_print
import requests
import json
from lib.settings import ssrf_or_redirect_params, vuln_level
from config import REVERSE_HTTP_IP, REVERSE_HTTP_PORT
dnslog_platform_address = "http://{}:{}/".format(
    REVERSE_HTTP_IP, REVERSE_HTTP_PORT)


class SSRFCheck:
    @staticmethod
    def check_get_ssrf(request):
        url = request.url
        dict = parse.parse_qs(parse.urlparse(url).query)
        for key, value in dict.items():
            if len(value) == 1:
                if "https://" in value[0] or "http://" in value[0] or key.lower(
                ) in ssrf_or_redirect_params:
                    token = random_str(20)
                    url1 = get_replaced_url(
                        url, dict[key][0], dnslog_platform_address, token)
                    try:
                        requests.get(url1, headers=request.headers, allow_redirects=False)
                    except BaseException:
                        pass
                    try:
                        check_ssrf_res = requests.get(
                            dnslog_platform_address + "_/search?q=" + token).text
                        if token in check_ssrf_res:
                            print("[+] " + url1 + " ssrf exists")
                            vuln_print(
                                url1, "ssrf", vuln_level["ssrf"], request.method)
                    except BaseException:
                        pass

    @staticmethod
    def check_post_urlencode_ssrf(request):
        url = request.url
        body = request.get_text()
        mid_url = "https://www.baidu.com?" + body
        dict = parse.parse_qs(parse.urlparse(mid_url).query)
        for key, value in dict.items():
            if len(value) == 1:
                if "https://" in value[0] or "http://" in value[0] or key.lower(
                ) in ssrf_or_redirect_params:
                    token = random_str(20)
                    dict[key][0] = dnslog_platform_address + token
                    try:
                        requests.post(url, data=dict, headers=request.headers)
                    except BaseException:
                        pass
                    try:
                        check_ssrf_res = requests.get(
                            dnslog_platform_address + "_/search?q=" + token).text
                        if token in check_ssrf_res:
                            print("[+] " + url + " ssrf exists")
                            vuln_print(
                                request.url,
                                "ssrf",
                                vuln_level["ssrf"],
                                request.method,
                                body)
                    except BaseException:
                        pass

    @staticmethod
    def check_post_json_ssrf(request):
        url = request.url
        body = request.get_text()
        dict = json.loads(body)
        for key, value in dict.items():
            if type(value).__name__ == "str":
                if "https://" in value or "http://" in value or key.lower() in ssrf_or_redirect_params:
                    token = random_str(20)
                    dict[key] = dnslog_platform_address + token
                    try:
                        requests.post(url, data=json.dumps(dict), headers=request.headers)
                    except BaseException:
                        pass
                    try:
                        check_ssrf_res = requests.get(
                            dnslog_platform_address + "_/search?q=" + token).text
                        if token in check_ssrf_res:
                            print("[+] " + url + " ssrf exists")
                            vuln_print(
                                request.url,
                                "ssrf",
                                vuln_level["ssrf"],
                                request.method,
                                body)
                    except BaseException:
                        pass

# if __name__ == "__main__":
#     check_post_json_ssrf("http://192.168.0.101:8080/ssrf","{\"no\":\"aaa\",\"url\":\"https://www.baidu.com/index.php?aa=qq\"}")
