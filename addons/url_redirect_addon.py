from lib.core.common import check_if_url_eligibility
from scanners.PerFile.url_redirect import UrlRedirectCheck
from multiprocessing import Process


class UrlRedirect:
    def __init__(self):
        self.all_urls = []

    @staticmethod
    def check_url_direct_task(request):
        UrlRedirectCheck().check_url_direct(request)

    def request(self, flow):
        request = flow.request
        if check_if_url_eligibility(request.url, self.all_urls):
            # print("[-]"+request.url+"不满足检测条件")
            return 0
        print("[" + request.method + "] URL重定向模块正在探测：" + request.url)
        p1 = Process(target=self.check_url_direct_task, args=(request,))
        p1.start()
