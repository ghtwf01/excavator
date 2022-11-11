from lib.core.spiderset import check_ext_if_pass, check_url_is_repeat, check_domain_is_forbid
from multiprocessing import Process
from scanners.PerFile.jsonp import Jsonp_Check

class JSONP:
    def __init__(self):
        self.url = ""
        self.method = ""
        self.all_urls = []
        self.sign = 0

    def check_jsonp_task(self, url, method, response_text):
        Jsonp_Check().check_jsonp(url, method, response_text)

    def request(self, flow):
        request = flow.request
        self.url = request.url
        self.method = request.method
        if (check_ext_if_pass(request.url) or check_url_is_repeat(request.url, self.all_urls) or check_domain_is_forbid(request.url)):
            # print("[-]"+request.url+"不满足检测条件")
            self.sign = 1
            return 0
        self.sign = 0
        print("[" + request.method + "] 敏感信息泄露模块正在探测：" + request.url)

    def response(self, flow):
        if self.sign == 1:
            return 0
        response = flow.response
        p1 = Process(target=self.check_jsonp_task, args=(self.url, self.method, response.text))
        p1.start()


