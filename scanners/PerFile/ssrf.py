from urllib import parse
from lib.core.common import random_str, get_replaced_url, vuln_print
import requests
import json
from lib.settings import ssrf_or_redirect_params, vuln_level
from config import REVERSE_HTTP_IP,REVERSE_HTTP_PORT
dnslog_platform_address = "http://{}:{}/".format(REVERSE_HTTP_IP,REVERSE_HTTP_PORT)

class SSRF_Check:
    def check_get_ssrf(self, request):
        url = request.url
        dict = parse.parse_qs(parse.urlparse(url).query)
        for key, value in dict.items():
            if len(value) == 1:
                if "https://" in value[0] or "http://" in value[0] or key.lower() in ssrf_or_redirect_params:
                    token = random_str(20)
                    url1 = get_replaced_url(url, dict[key][0], dnslog_platform_address, token)
                    requests.get(url1, allow_redirects=False)
                    check_ssrf_res = requests.get(dnslog_platform_address + "_/search?q=" + token).text
                    if token in check_ssrf_res:
                        print("[+] " + url1 + " ssrf exists")
                        vuln_print(url1, "ssrf", vuln_level["ssrf"], request.method)

    def check_post_urlencode_ssrf(self, request):
        url = request.url
        body = request.get_text()
        mid_url = "https://www.baidu.com?"+body
        dict = parse.parse_qs(parse.urlparse(mid_url).query)
        for key, value in dict.items():
            if len(value) == 1:
                if "https://" in value[0] or "http://" in value[0] or key.lower() in ssrf_or_redirect_params:
                    token = random_str(20)
                    dict[key][0] = dnslog_platform_address + token
                    requests.post(url, data=dict)
                    check_ssrf_res = requests.get(dnslog_platform_address + "_/search?q=" + token).text
                    if token in check_ssrf_res:
                        print("[+] " + url + " ssrf exists")
                        vuln_print(request.url, "ssrf", vuln_level["ssrf"], request.method, dict)

    def check_post_json_ssrf(self, request):
        url = request.url
        body = request.get_text()
        dict = json.loads(body)
        for key, value in dict.items():
            if type(value).__name__ == "str":
                if "https://" in value or "http://" in value or key.lower() in ssrf_or_redirect_params:
                    token = random_str(20)
                    dict[key] = dnslog_platform_address + token
                    headers = {"Content-Type":"application/json"}
                    requests.post(url, data=json.dumps(dict), headers=headers)
                    check_ssrf_res = requests.get(dnslog_platform_address + "_/search?q=" + token).text
                    if token in check_ssrf_res:
                        print("[+] " + url + " ssrf exists")
                        vuln_print(request.url, "ssrf", vuln_level["ssrf"], request.method, dict)

# if __name__ == "__main__":
#     check_post_json_ssrf("http://192.168.0.101:8080/ssrf","{\"no\":\"aaa\",\"url\":\"https://www.baidu.com/index.php?aa=qq\"}")