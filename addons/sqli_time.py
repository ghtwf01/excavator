from lib.core.common import get_content_type
from lib.core.spiderset import *
from scanners.PerFile.sqli_time import SQLI
class SQLI_Time:
    def __init__(self):
        self.all_urls = []
    def request(self, flow):
        request = flow.request
        if (check_ext_if_pass(request.url) or check_url_is_repeat(request.url, self.all_urls) or check_domain_is_forbid(request.url)):
            # print("[-]"+request.url+"不满足检测条件")
            return 0
        print("[" + request.method + "] SQL盲注注入模块正在探测：" + request.url)
        if request.method == "GET":
            SQLI().check_get_time_sqli(request)
        if request.method == "POST":
            content_type = get_content_type(request)
            if "application/x-www-form-urlencoded" in content_type:
                SQLI().check_post_urlencode_sqli(request)
            if "application/json" in content_type:
                SQLI().check_post_json_sqli(request)