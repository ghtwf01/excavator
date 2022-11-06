from lib.core.spiderset import *
from scanners.PerFile.ssrf import SSRF_Check
from lib.core.common import get_content_type
class SSRF:
    def __init__(self):
        self.all_urls = []
    def request(self, flow):
        request = flow.request
        if (check_ext_if_pass(request.url) or check_url_is_repeat(request.url, self.all_urls) or check_domain_is_forbid(request.url)):
            # print("[-]"+request.url+"不满足检测条件")
            return 0
        print("[" + request.method + "] SSRF模块正在探测：" + request.url)
        if request.method == "GET":
            SSRF_Check().check_get_ssrf(request)
        if request.method == "POST":
            content_type = get_content_type(request)
            if "application/x-www-form-urlencoded" in content_type:
                SSRF_Check().check_post_urlencode_ssrf(request)
            if "application/json" in content_type:
                SSRF_Check().check_post_json_ssrf(request)