from lib.core.common import vuln_print
from lib.settings import vuln_level

class Cors_Check:
    def check_cors(self, response, url, method):
        try:
            access_credentials = response.headers["Access-Control-Allow-Credentials"]
            access_origin = response.headers["Access-Control-Allow-Origin"]
            if (access_origin == "*" or access_origin == "https://www.test.com") and access_credentials == "true":
                vuln_print(url, "cors", vuln_level["cors"], method, str(dict))
        except:
            pass

