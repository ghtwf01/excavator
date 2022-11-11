from lib.core.common import get_content_type
from lib.core.spiderset import check_ext_if_pass, check_url_is_repeat, check_domain_is_forbid
from scanners.PerFile.unauth import Unauth_Check
from multiprocessing import Process

class Unauth:
    def __init__(self):
        self.all_urls = []
        self.sign = 0
        self.req_headers = []
        self.url = ""
        self.body = ""
        self.method = ""
        self.content_type = ""
    def check_get_unauth_task(self, url, req_headers, method, response_text):
        Unauth_Check().check_get_unauth(url, req_headers, method, response_text)

    def check_post_urlencode_unauth_task(self, url, req_headers, method, body, response_text):
        Unauth_Check().check_post_urlencode_unauth(url, req_headers, method, body, response_text)

    def check_post_json_unauth_task(self, url, req_headers, method, body, response_text):
        Unauth_Check().check_post_json_unauth(url, req_headers, method, body, response_text)

    def request(self, flow):
        request = flow.request
        self.req_headers = request.headers
        self.url = request.url
        self.method = request.method
        try:
            self.content_type = request.headers['Content-Type']
            self.content_type = request.headers['content-type']
        except:
            pass
        self.body = request.get_text()
        if (check_ext_if_pass(request.url) or check_url_is_repeat(request.url, self.all_urls) or check_domain_is_forbid(request.url)):
            # print("[-]"+request.url+"不满足检测条件")
            self.sign = 1
            return 0
        self.sign = 0
        print("[" + request.method + "] 未授权访问模块正在探测：" + request.url)

    def response(self, flow):
        if self.sign == 1:
            return 0
        response = flow.response
        if self.method == "GET":
            p1 = Process(target=self.check_get_unauth_task, args=(self.url, self.req_headers, self.method, response.text))
            p1.start()
        if self.method == "POST":
            if "application/x-www-form-urlencoded" in self.content_type:
                p1 = Process(target=self.check_post_urlencode_unauth_task, args=(self.url, self.req_headers, self.method, self.body, response.text))
                p1.start()
            if "application/json" in self.content_type:
                p1 = Process(target=self.check_post_json_unauth_task, args=(self.url, self.req_headers, self.method, self.body, response.text))
                p1.start()


