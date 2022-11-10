from addons.ssrf_addon import SSRF
from addons.information_disclosure_addon import Information_disclosure
from addons.url_redirect_addon import Url_redirect
from addons.xss_addon import XSS
from addons.sqli_error_addon import SQLI_Error
from addons.sqli_time_addon import SQLI_Time
from addons.cors_addon import Cors
# from addons.jsonp_addon import JSONP
addons = [
    SSRF(), Information_disclosure(), Url_redirect(), XSS(), SQLI_Error(), SQLI_Time(), Cors()
]
