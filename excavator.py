import os
from lib.core.common import recharge_report
recharge_report()
addon_path = os.getcwd()+"/addon.py"
print("Proxy server listening at http://*:8080")
os.system("mitmdump -q -s "+addon_path)
