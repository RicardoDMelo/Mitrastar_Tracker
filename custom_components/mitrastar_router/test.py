# import base64
# import re
# import requests
# import hashlib
# from http.cookies import SimpleCookie
#
# username1 = str('bbbbbbbbbbb')
# password1 = str('aaaaaaaaaaaa')
# sid = '26db0ff7'
# text_to_hash = '{0}:{1}'.format(sid, password1)
# md5_hash = hashlib.md5(text_to_hash.encode('utf-8'))
# hashed_pwd = md5_hash.hexdigest()
#
# session_key = base64.b64encode(
#     '{user}:{pass}'.format(**{
#         'user': username1,
#         'pass': hashed_pwd
#     }).encode()
# )
#
# data1 = {
#     'sessionKey': session_key,
#     'user': username1,
#     'pass': ''
# }
# host = '192.168.15.1'
# LOGIN_URL = 'http://{ip}/login-login.cgi'.format(**{'ip': host})
# headers1 = {
#     'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36',
#     'referer': 'http://192.168.15.1/login_frame.html',
#     'content-type': 'application/x-www-form-urlencoded',
#     'DNT': '1',
#     'Upgrade-Insecure-Requests': '1',
#     'Host': '192.168.15.1',
#     'Origin': 'http://192.168.15.1'
# }
# parse_macs = re.compile(r'([0-9a-fA-F]{2}:' + '[0-9a-fA-F]{2}:' + '[0-9a-fA-F]{2}:' + '[0-9a-fA-F]{2}:' + '[0-9a-fA-F]{2}:' + '[0-9a-fA-F]{2})')
# parse_dhcp = re.compile(r'<td>([0-9a-zA-Z\-._]+)</td><td>([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})</td><td>([0-9]+.[0-9]+.[0-9]+.[0-9]+.[0-9]+)')
#
#
# def test():
#     session1 = requests.Session()
#     login_response = session1.post(LOGIN_URL, data=data1, headers=headers1)
#
#     if login_response.status_code == 200:
#         cookies = SimpleCookie(login_response.headers['Set-Cookie'])
#
#         session1.cookies.set("SESSION", cookies["SESSION"].value, domain=host)
#         # session1.cookies.set_cookie(cookies["SESSION"])
#         url1 = 'http://{}/wlextstationlist.cmd?action=view&wlSsidIdx=2'.format(host)
#         url2 = 'http://{}/wlextstationlist.cmd?action=view&wlSsidIdx=1'.format(host)
#         url3 = 'http://{}/arpview.cmd'.format(host)
#         url4 = 'http://{}/dhcpinfo.html'.format(host)
#
#         result1 = _read_table(session1, url1).lower()
#         mac_address1 = parse_macs.findall(result1)
#
#         result2 = _read_table(session1, url2).lower()
#         mac_address2 = parse_macs.findall(result2)
#
#         result3 = _read_table(session1, url3).lower()
#         mac_address3 = parse_macs.findall(result3)
#
#         result4 = _read_table(session1, url4)
#         result4 = result4.replace('\n ', '').replace(' ', '')
#         hostnames = parse_dhcp.findall(result4)
#
#         mac_address1.extend([element for element in mac_address2 if element not in mac_address1])
#         mac_address1.extend([element for element in mac_address3 if element not in mac_address1])
#         print('MitraStar GPT-2541GNAC Router: Found %d devices' % len(mac_address1))
#
#     else:
#         mac_address1 = None
#         hostnames = None
#         print('Error connecting to the router...')
#
#
# def _read_table(session, url):
#     response = session.get(url, headers=headers1)
#     if response.status_code == 200:
#         response_string = str(response.content, 'utf-8''')
#         return response_string
#     else:
#         print('Error trying to connect to url: {status} {url}'.format(**{'url': url, 'status': response.status_code}))
#         return ''
#
# test()
#
