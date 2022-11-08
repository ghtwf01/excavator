from urllib import parse
from lib.core.common import vuln_print, get_replaced_url
import requests
from lib.settings import ssrf_or_redirect_params, vuln_level
class Url_Redirect_Check:
    def check_url_direct(self, request):
        url = request.url
        dict = parse.parse_qs(parse.urlparse(url).query)
        redirect_url = "https://example.com"
        for key, value in dict.items():
            if len(value) == 1:
                if "https://" in value[0] or "http://" in value[0] or key.lower() in ssrf_or_redirect_params:
                    url1 = get_replaced_url(url, dict[key][0], redirect_url)
                    headers = requests.get(url1, allow_redirects=False).headers
                    try:
                        if headers["Location"] == "https://example.com":
                            print("[+] " + url1 + " url redirect exists")
                            vuln_print(url1, "url_redirect", vuln_level["url_redirect"], request.method)
                    except:
                        pass