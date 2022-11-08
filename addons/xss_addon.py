from lib.core.spiderset import *
from scanners.PerFile.xss import MyHTMLParser
from multiprocessing import Process
import requests
class XSS:
    def __init__(self):
        self.all_urls = []
    def check_xss_task(self, request):
        content_type = requests.get(request.url).headers["Content-Type"]
        if "application/json" in content_type:
            # print("返回包content-type不满足xss检测")
            return 0
        MyHTMLParser().check_xss(request)
    def request(self, flow):
        request = flow.request
        if (check_ext_if_pass(request.url) or check_url_is_repeat(request.url, self.all_urls) or check_domain_is_forbid(request.url)):
            # print("[-]"+request.url+"不满足检测条件")
            return 0
        print("[" + request.method + "] XSS模块正在探测：" + request.url)
        if request.method == "GET":
            p1 = Process(target=self.check_xss_task, args=(request,))
            p1.start()
