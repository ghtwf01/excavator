from addons.ssrf_addon import SSRF
from addons.html_res_information_disclosure_addon import InformationDisclosure
from addons.url_redirect_addon import UrlRedirect
from addons.xss_addon import XSS
from addons.sqli_error_addon import SQLIError
from addons.sqli_time_addon import SQLITime
from addons.cors_addon import Cors
from addons.jsonp_addon import JSONP
from addons.file_read_addon import FileRead
from addons.unauth_addon import UnAuth

addons = [
    SSRF(),
    InformationDisclosure(),
    UrlRedirect(),
    XSS(),
    SQLIError(),
    SQLITime(),
    Cors(),
    JSONP(),
    FileRead()
]
