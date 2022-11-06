from lib.core.spiderset import *
from scanners.PerFile.information_disclosure import Information_Check
from lib.core.common import get_content_type
class Information_disclosure:
    def __init__(self):
        self.sign = 0
        self.all_urls = []
        self.url = ""
        self.method = ""
        self.body = ""
    def request(self, flow):
        request = flow.request
        self.url = request.url
        self.method = request.method
        self.body = request.get_text()
        if (check_ext_if_pass(request.url) or check_url_is_repeat(request.url, self.all_urls) or check_domain_is_forbid(request.url)):
            # print("[-]"+request.url+"不满足检测条件")
            self.sign = 1
            return 0
        print("[" + request.method + "] 敏感信息泄露模块正在探测：" + request.url)
    def response(self, flow):
        if self.sign == 1:
            return 0
        response = flow.response
        content_type = get_content_type(response)
        if "application/xml" in content_type or "application/json" in content_type:
            Information_Check().check_information_disclosure(str(response.text), self.url, self.method, self.body)