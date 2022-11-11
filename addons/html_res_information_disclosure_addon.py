from scanners.PerFile.html_res_information_disclosure import HtmlInformationCheck
from lib.core.common import get_content_type, check_if_url_eligibility
from multiprocessing import Process


class InformationDisclosure:
    def __init__(self):
        self.sign = 0
        self.all_urls = []
        self.url = ""
        self.method = ""
        self.body = ""

    @staticmethod
    def check_information_disclosure_task(
            response_html, url, method, body):
        HtmlInformationCheck().check_information_disclosure(response_html, url, method, body)

    def request(self, flow):
        request = flow.request
        self.url = request.url
        self.method = request.method
        self.body = request.get_text()
        if check_if_url_eligibility(request.url, self.all_urls):
            # print("[-]"+request.url+"不满足检测条件")
            self.sign = 1
            return 0
        self.sign = 0
        print("[" + request.method + "] 敏感信息泄露模块正在探测：" + request.url)

    def response(self, flow):
        if self.sign == 1:
            return 0
        response = flow.response
        content_type = get_content_type(response)
        response_html = str(response.text)
        if "application/xml" in content_type or "application/json" in content_type:
            p1 = Process(
                target=self.check_information_disclosure_task,
                args=(
                    response_html,
                    self.url,
                    self.method,
                    self.body))
            p1.start()
