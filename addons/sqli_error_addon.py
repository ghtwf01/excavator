from lib.core.common import get_content_type, check_if_url_eligibility
from scanners.PerFile.sqli_error import SQLIErrorCheck
from multiprocessing import Process


class SQLIError:
    def __init__(self):
        self.all_urls = []

    @staticmethod
    def check_get_error_sqli_task(request):
        SQLIErrorCheck().check_get_error_sqli(request)

    @staticmethod
    def check_post_urlencode_error_sqli_task(request):
        SQLIErrorCheck().check_post_urlencode_error_sqli(request)

    @staticmethod
    def check_post_json_error_sqli_task(request):
        SQLIErrorCheck().check_post_json_error_sqli(request)

    def request(self, flow):
        request = flow.request
        if check_if_url_eligibility(request.url, self.all_urls):
            # print("[-]"+request.url+"不满足检测条件")
            return 0
        print("[" + request.method + "] SQL报错注入模块正在探测：" + request.url)
        if request.method == "GET":
            p1 = Process(
                target=self.check_get_error_sqli_task,
                args=(
                    request,
                ))
            p1.start()
        if request.method == "POST":
            content_type = get_content_type(request)
            if "application/x-www-form-urlencoded" in content_type:
                p1 = Process(
                    target=self.check_post_urlencode_error_sqli_task,
                    args=(
                        request,
                    ))
                p1.start()
            if "application/json" in content_type:
                p1 = Process(
                    target=self.check_post_json_error_sqli_task,
                    args=(
                        request,
                    ))
                p1.start()
