from lib.core.common import check_if_url_eligibility
from scanners.PerFile.unauth import UnAuthCheck
from multiprocessing import Process


class UnAuth:
    def __init__(self):
        self.all_urls = []
        self.sign = 0
        self.req_headers = []
        self.url = ""
        self.body = ""
        self.method = ""
        self.content_type = ""

    @staticmethod
    def check_get_unauth_task(url, req_headers, method, response_text):
        UnAuthCheck().check_get_unauth(url, req_headers, method, response_text)

    @staticmethod
    def check_post_urlencode_unauth_task(
            url, req_headers, method, body, response_text):
        UnAuthCheck().check_post_urlencode_unauth(
            url, req_headers, method, body, response_text)

    @staticmethod
    def check_post_json_unauth_task(
            url,
            req_headers,
            method,
            body,
            response_text):
        UnAuthCheck().check_post_json_unauth(
            url, req_headers, method, body, response_text)

    def request(self, flow):
        request = flow.request
        self.req_headers = request.headers
        self.url = request.url
        self.method = request.method
        try:
            self.content_type = request.headers['Content-Type']
            self.content_type = request.headers['content-type']
        except BaseException:
            pass
        self.body = request.get_text()
        if check_if_url_eligibility(request.url, self.all_urls):
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
            p1 = Process(
                target=self.check_get_unauth_task,
                args=(
                    self.url,
                    self.req_headers,
                    self.method,
                    response.text))
            p1.start()
        if self.method == "POST":
            if "application/x-www-form-urlencoded" in self.content_type:
                p1 = Process(target=self.check_post_urlencode_unauth_task, args=(
                    self.url, self.req_headers, self.method, self.body, response.text))
                p1.start()
            if "application/json" in self.content_type:
                p1 = Process(
                    target=self.check_post_json_unauth_task,
                    args=(
                        self.url,
                        self.req_headers,
                        self.method,
                        self.body,
                        response.text))
                p1.start()
