from html.parser import HTMLParser
import requests
from urllib import parse
from lib.core.common import random_str, get_replaced_url, vuln_print
from bs4 import BeautifulSoup

from lib.settings import vuln_level


class MyHTMLParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.position = []
        self.tag = ""
        self.body_tag = ""
        self.method = ""
    def handle_starttag(self, tag, attrs):
        self.tag = tag
        try:
            for attr in attrs:
                if "aSdfGd" in attr[1]:
                    if attr[0] == "href":
                        print("回显字符串位于href标签值中")
                        self.position.append("href")
                    else:
                        print("回显字符串位于属性值中")
                        self.position.append("value")
        except:
            pass
    def handle_data(self, data):
        if "aSdfGd" in data:
            self.body_tag = self.tag
            print("回显字符串位于"+self.body_tag+"标签内")
            self.position.append("body")
    def handle_comment(self, data):
        if "aSdfGd" in data:
            print("回显字符串位于注释中")
            self.position.append("comment")
    def check_value_xss(self, url, value, type, headers):
        url_value1_single = get_replaced_url(url, value, '"psafq="g')
        res1_single = requests.get(url_value1_single, headers=headers).text
        soup = BeautifulSoup(res1_single, "html.parser")
        if soup.find(psafq="g"):
            print("payload：\"OnMoUsEoVeR=confirm()//")
            vuln_print(url_value1_single, "xss", vuln_level["xss"], self.method)
        url_value2_single = get_replaced_url(url, value, '"><arcbvyf>')
        res2_single = requests.get(url_value2_single, headers=headers).text
        soup = BeautifulSoup(res2_single, "html.parser")
        if soup.find("arcbvyf"):
            print("payload：\"><img src=1>")
            vuln_print(url_value2_single, "xss", vuln_level["xss"], self.method)

        url_value3_single = get_replaced_url(url, value, "'psafq=\"g")
        res3_single = requests.get(url_value3_single, headers=headers).text
        soup = BeautifulSoup(res3_single, "html.parser")
        if soup.find(psafq="g"):
            print("payload：'OnMoUsEoVeR=confirm()//")
            vuln_print(url_value3_single, "xss", vuln_level["xss"], self.method)
        url_value4_single = get_replaced_url(url, value, "'><arcbvyf>")
        res4_single = requests.get(url_value4_single, headers=headers).text
        soup = BeautifulSoup(res4_single, "html.parser")
        if soup.find("arcbvyf"):
            print("payload：'><img src=1>")
            vuln_print(url_value4_single, "xss", vuln_level["xss"], self.method)
        if type == "href":
            url_href = get_replaced_url(url, value, "aaaa:bbbb(1)")
            res = requests.get(url_href, headers=headers).text
            soup = BeautifulSoup(res, "html.parser")
            if soup.find(href="aaaa:bbbb(1)"):
                print("payload：javascript:alert(1)")
                vuln_print(url_href, "xss", vuln_level["xss"], self.method)

    def check_body_xss(self, url, value, headers):
        if self.body_tag == "script":
            url_body1 = get_replaced_url(url, value, ';arcbvyf;//')
            html = requests.get(url_body1, headers=headers).text
            if ";arcbvyf;//" in html:
                print("payload：;alert(1);//")
                vuln_print(url_body1, "xss", vuln_level["xss"], self.method)
            url_body2 = get_replaced_url(url, value, '</' + self.body_tag + '>' + '<arcbvyf>')
            res2 = requests.get(url_body2, headers=headers).text
            soup = BeautifulSoup(res2, "html.parser")
            if soup.find("arcbvyf"):
                print("payload：" + "</" + self.body_tag + ">" + "<img src=1>")
                vuln_print(url_body2, "xss", vuln_level["xss"], self.method)
        else:
            url_body2 = get_replaced_url(url, value, '</'+self.body_tag+'>'+'<arcbvyf>')
            res2 = requests.get(url_body2, headers=headers).text
            soup = BeautifulSoup(res2, "html.parser")
            if soup.find("arcbvyf"):
                print("payload："+"</"+self.body_tag+">"+"<img src=1>")
                vuln_print(url_body2, "xss", vuln_level["xss"], self.method)
    def check_comment_xss(self, url, value, headers):
        url_comment = get_replaced_url(url, value, '--><arcbvyf>')
        res = requests.get(url_comment, headers=headers).text
        soup = BeautifulSoup(res, "html.parser")
        if soup.find("arcbvyf"):
            print("payload：--><img src=1>")
            vuln_print(url_comment, "xss", vuln_level["xss"], self.method)

    def check_xss(self, request):
        url = request.url
        self.method = request.method
        dict = parse.parse_qs(parse.urlparse(url).query)
        for key, value in dict.items():
            if len(value) == 1:
                url1 = get_replaced_url(url, dict[key][0], "aSdfGd")
                html = requests.get(url1, headers=request.headers).text
                if "aSdfGd" in html:
                    soup = BeautifulSoup(html, "html.parser")
                    soup.find_all("aSdfGd")
                    self.feed(html)
                    if len(self.position) != 0:
                        if len(self.position) == 1:
                            if self.position[0] == "value" or self.position[0] == "href":
                                self.check_value_xss(url, dict[key][0], self.position[0], headers=request.headers)
                            if self.position[0] == "body":
                                self.check_body_xss(url, dict[key][0], headers=request.headers)
                            if self.position[0] == "comment":
                                self.check_comment_xss(url, dict[key][0], headers=request.headers)