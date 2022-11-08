from scanners.PerFile.cors import Cors_Check
from lib.core.spiderset import *
class Cors:
    def __init__(self):
        self.sign = 0
        self.all_urls = []
        self.url = ""
        self.method = ""

    def request(self, flow):
        request = flow.request
        self.url = request.url
        self.method = request.method
        if (check_ext_if_pass(request.url) or check_url_is_repeat(request.url, self.all_urls) or check_domain_is_forbid(request.url)):
            self.sign = 1
            return 0
        self.sign = 0
        request.headers["Origin"] = "https://www.test.com"
        print("[" + request.method + "] CORS模块正在探测：" + request.url)

    def response(self, flow):
        if self.sign == 1:
            return 0
        response = flow.response
        Cors_Check().check_cors(response, self.url, self.method)