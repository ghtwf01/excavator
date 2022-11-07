from lib.settings import notAcceptedExt
from urllib.parse import urlparse
from config import EXCLUDES
from urllib import parse
def check_ext_if_pass(url):
    try:
        scheme = parse.urlparse(url).scheme
        netloc = parse.urlparse(url).netloc
        path = parse.urlparse(url).path
        url = scheme + "://" + netloc + path
        ext = url.split(".")[-1]
        if ext in notAcceptedExt:
            return True
        else:
            return False
    except:
        pass
def check_url_is_repeat(url, all_urls):
    url = etl(url)
    if url in all_urls:
        # print(url + " 已有记录")
        return True
    else:
        all_urls.append(url)
        return False
def check_domain_is_forbid(url):
    domain = urlparse(url).netloc
    for forbid_key in EXCLUDES:
        if forbid_key in domain:
            return True
    return False
def etl(str, onlyNUM=False):
    '''
    传入一个字符串，将里面的字母转化为A，数字转化为N，特殊符号转换为T，其他符号或者字符转化成C
    :param str:
    :param onlyNUM:只换数字
    :return:
    '''
    Chars = [',', '-', '_']
    chars = ""
    for c in str:
        c = c.lower()
        if not onlyNUM:
            if ord('a') <= ord(c) <= ord('z') and not onlyNUM:
                chars += 'A'
            elif ord('0') <= ord(c) <= ord('9'):
                chars += 'N'
            elif c in Chars:
                chars += 'T'
            else:
                chars += 'C'
        else:
            if ord('0') <= ord(c) <= ord('9'):
                chars += 'N'
            else:
                chars += c
    return chars