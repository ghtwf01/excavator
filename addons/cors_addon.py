from scanners.PerFile.cors import CorsCheck
from lib.core.common import check_if_url_eligibility


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
        if check_if_url_eligibility(request.url, self.all_urls):
            self.sign = 1
            # print("[-]"+request.url+"不满足检测条件")
            return 0
        self.sign = 0
        request.headers["Origin"] = "https://www.test.com"
        print("[" + request.method + "] CORS模块正在探测：" + request.url)

    def response(self, flow):
        if self.sign == 1:
            return 0
        response = flow.response
        CorsCheck().check_cors(response, self.url, self.method)
