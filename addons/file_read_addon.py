from lib.core.common import get_content_type
from lib.core.spiderset import *
from scanners.PerFile.file_read import File_Read_Check
from multiprocessing import Process
class File_Read:
    def __init__(self):
        self.all_urls = []
    def check_get_file_read_task(self, request):
        File_Read_Check().check_get_file_read(request)

    def check_post_urlencode_file_read_task(self, request):
        File_Read_Check().check_post_urlencode_file_read(request)

    def check_post_json_file_read_task(self, request):
        File_Read_Check().check_post_json_file_read(request)

    def request(self, flow):
        request = flow.request
        if (check_ext_if_pass(request.url) or check_url_is_repeat(request.url, self.all_urls) or check_domain_is_forbid(request.url)):
            # print("[-]"+request.url+"不满足检测条件")
            return 0
        print("[" + request.method + "] 任意文件读取模块正在探测：" + request.url)
        if request.method == "GET":
            p1 = Process(target=self.check_get_file_read_task, args=(request,))
            p1.start()
        if request.method == "POST":
            content_type = get_content_type(request)
            if "application/x-www-form-urlencoded" in content_type:
                p1 = Process(target=self.check_post_urlencode_file_read_task, args=(request,))
                p1.start()
            if "application/json" in content_type:
                p1 = Process(target=self.check_post_json_file_read_task, args=(request,))
                p1.start()
