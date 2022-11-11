from lib.core.common import check_if_url_eligibility
from multiprocessing import Process
from scanners.PerFile.jsonp import JsonpCheck


class JSONP:
    def __init__(self):
        self.url = ""
        self.method = ""
        self.all_urls = []
        self.sign = 0

    @staticmethod
    def check_jsonp_task(url, method, response_text):
        JsonpCheck().check_jsonp(url, method, response_text)

    def request(self, flow):
        request = flow.request
        self.url = request.url
        self.method = request.method
        if check_if_url_eligibility(request.url, self.all_urls):
            # print("[-]"+request.url+"不满足检测条件")
            self.sign = 1
            return 0
        self.sign = 0
        print("[" + request.method + "] jsonp劫持模块正在探测：" + request.url)

    def response(self, flow):
        if self.sign == 1:
            return 0
        response = flow.response
        p1 = Process(
            target=self.check_jsonp_task,
            args=(
                self.url,
                self.method,
                response.text))
        p1.start()
