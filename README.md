![excavator](https://socialify.git.ci/ghtwf01/excavator/image?description=1&forks=1&issues=1&language=1&name=1&owner=1&pattern=Signal&stargazers=1&theme=Light)

# excavator
ps：项目持续更新ing

excavator是一款基于mitmproxy的插件式被动安全漏洞扫描器，此项目参考xray、w13scan、sqlmap等优秀工具的部分检测逻辑及规则以及结合个人web渗透及研究经验使用python3开发而成，可运行在Windows、Linux、MacOS上，主要功能是发现Web中的安全漏洞。
# 免责声明
请勿将本项目技术或代码应用在恶意软件制作、软件著作权/知识产权盗取或不当牟利等非法用途中。实施上述行为或利用本项目对非自己著作权所有的程序进行数据嗅探将涉嫌违反《中华人民共和国刑法》第二百一十七条、第二百八十六条，《中华人民共和国网络安全法》《中华人民共和国计算机软件保护条例》等法律规定。本项目提及的技术仅可用于私人学习测试等合法场景中，任何不当利用该技术所造成的刑事、民事责任均与本项目作者无关。
# 运行原理
![流程图](https://user-images.githubusercontent.com/56472384/200158555-091c065e-6f31-40ca-ac9d-0358dad79411.png)
# 检测插件
- [x] XSS检测
    - 基于语义的XSS扫描
- [x] SQL注入检测
    - 覆盖POST请求包中Content-Type为application/x-www-form-urlencoded和application/json的检测
    - 基于报错SQL注入检测
    - <del>基于网页相似度布尔类型的SQL注入检测</del>
    - 基于时间SQL注入检测
- [x] SSRF检测
    - 覆盖POST请求包中Content-Type为application/x-www-form-urlencoded和application/json的检测
    - 正则匹配url替换检测+常见SSRF参数检测
- [x] URL重定向检测
    - 正则匹配url替换检测+常见URL重定向参数检测
- [x] 敏感信息泄露检测
    - [x] 返回包中敏感信息泄露，正则配合Content-Type检测，减少误报
    - [ ] http请求包中敏感数据传输(AK/SK、api_key等)
    - [ ] 敏感文件泄露(.git、备份文件等)
- [x] CORS配置不当检测
- [x] JSONP劫持检测
    - 检测JSONP特征存在+替换Referer判断是否有劫持风险
- [ ] 任意文件读取检测
- [ ] 远程代码/命令执行检测
- [ ] 文件上传检测
- [ ] 未授权访问检测
- [ ] 越权检测
- [ ] 通用cve漏洞poc检测
- [ ] 等等
# 使用方式
```python
# 首次使用安装依赖
pip3 install -r requirements.txt
# 开启反连平台，可检测SSRF(可选)，反连平台这里使用的是w13scan的反连平台
python3 reverse.py
# 启动excavator
python3 excavator.py
# 开始人工测试网站或者开启爬虫，如联动rad爬虫
./rad_darwin_amd64 -t http://testphp.vulnweb.com/ -http-proxy 127.0.0.1:8080
# 更多联动方式可参考xray文档：https://docs.xray.cool/#/scenario/burp
```
启动后会开启本地8080端口监听，代理流量进8080端口即可
vulnweb扫描报告可见：https://github.com/ghtwf01/excavator/blob/main/report/res_example.txt
# 反连平台
如果要启动反连平台，需要在config.py里将REVERSE_HTTP_IP改为自己的公网ip(内网探测改为内网ip)即可，端口可自定义
# 证书安装
如果需要导入证书，在启动excavator.py后开启浏览器代理访问http://mitm.it ，下载对应操作系统下的证书即可
![pem](https://user-images.githubusercontent.com/56472384/200172366-d6a5a83e-e3af-4574-a97b-465a7547dfd7.png)
# 展望&目标
挖洞好帮手，成为真正的excavator
# 优点
手工测试时利用浏览器代理可实现登陆态漏洞检测，浏览器访问页面时请求的所有接口都会被检测，大大增加了检测面
非手工测试时使用爬虫流量导入excavator也很方便

总结：覆盖手工、非手工场景，亲民
# 优化todo
- [ ] html报告输出
- [ ] 增加用户自定义参数，如指定检测模块、自定义监听端口等
- [ ] 增加代理扫描
- [ ] 增加excavator的检测插件
- [ ] 持续优化代码
# 参考&致谢
https://github.com/w-digital-scanner/w13scan

https://github.com/amcai/myscan
