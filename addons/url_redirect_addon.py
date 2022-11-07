from lib.core.spiderset import *
from scanners.PerFile.url_redirect import Url_Redirect
from multiprocessing import Process
class Url_redirect:
    def __init__(self):
        self.all_urls = []
    def check_url_direct_task(self, request):
        Url_Redirect().check_url_direct(request)
    def request(self, flow):
        request = flow.request
        if (check_ext_if_pass(request.url) or check_url_is_repeat(request.url, self.all_urls) or check_domain_is_forbid(request.url)):
            # print("[-]"+request.url+"不满足检测条件")
            return 0
        print("[" + request.method + "] URL重定向模块正在探测：" + request.url)
        p1 = Process(target=self.check_url_direct_task, args=(request,))
        p1.start()
