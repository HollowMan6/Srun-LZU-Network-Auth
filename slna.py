#!/usr/bin/python3
# -*- coding:utf-8 -*-
# by 'hollowman6' from Lanzhou University(兰州大学)

import re
import sys
import time
import getpass
import requests
import hashlib
import hmac
import math
import getopt
from urllib import parse


'''
 Return Code
'''

return_code_zh_CN = {
    "E2901: (Third party 1)bind_user2: ldap_bind error": "账号或密码错误",
    "E2901: (Third party 1)ldap_first_entry error": "账号或密码错误",
    "E2901: (Third party 1){": "账号或密码错误",
    "CHALLENGE failed, BAS respond timeout.": "网络连接超时，请稍后重试",
    "INFOError锛宔rrCode=2": "设备不在认证区域内",
}

return_code_en_US = {
    "E2901: (Third party 1)bind_user2: ldap_bind error": "Incorrect username or password",
    "E2901: (Third party 1)ldap_first_entry error": "Incorrect username or password",
    "E2901: (Third party 1){": "Incorrect username or password",
    "CHALLENGE failed, BAS respond timeout.": "Network connection timed out, please try again later",
    "INFOError锛宔rrCode=2": "The device is not within the scope of certification"
}

'''
 For Xlencode Encryption
'''


def force(msg):
    ret = []
    for w in msg:
        ret.append(ord(w))
    return bytes(ret)


def ordat(msg, idx):
    if len(msg) > idx:
        return ord(msg[idx])
    return 0


def sencode(msg, key):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i) | ordat(msg, i + 1) << 8 | ordat(msg, i + 2) << 16
            | ordat(msg, i + 3) << 24)
    if key:
        pwd.append(l)
    return pwd


def lencode(msg, key):
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return
        ll = m
    for i in range(0, l):
        msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
            msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
    if key:
        return "".join(msg)[0:ll]
    return "".join(msg)


def get_xencode(msg, key):
    if msg == "":
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    c = 0x86014019 | 0x183639A0
    m = 0
    e = 0
    p = 0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return lencode(pwd, False)


'''
 For Base64 Encryption
'''

_PADCHAR = "="
_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"


def _getbyte(s, i):
    x = ord(s[i])
    if (x > 255):
        print("INVALID_CHARACTER_ERR: DOM Exception 5")
        exit(0)
    return x


def get_base64(s):
    i = 0
    b10 = 0
    x = []
    imax = len(s) - len(s) % 3
    if len(s) == 0:
        return s
    for i in range(0, imax, 3):
        b10 = (_getbyte(s, i) << 16) | (
            _getbyte(s, i + 1) << 8) | _getbyte(s, i + 2)
        x.append(_ALPHA[(b10 >> 18)])
        x.append(_ALPHA[((b10 >> 12) & 63)])
        x.append(_ALPHA[((b10 >> 6) & 63)])
        x.append(_ALPHA[(b10 & 63)])
    i = imax
    if len(s) - imax == 1:
        b10 = _getbyte(s, i) << 16
        x.append(_ALPHA[(b10 >> 18)] +
                 _ALPHA[((b10 >> 12) & 63)] + _PADCHAR + _PADCHAR)
    else:
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8)
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)
                                              ] + _ALPHA[((b10 >> 6) & 63)] + _PADCHAR)
    return "".join(x)


'''
 For MD5 Encryption
'''


def get_md5(password, token):
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()


'''
 For SHA1 Encryption
'''


def get_sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()


'''
 For Login
'''

header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36'
}

login_url = "http://10.10.0.166"
get_challenge_api = parse.urljoin(login_url, "/cgi-bin/get_challenge")
srun_portal_login_api = parse.urljoin(login_url, "/cgi-bin/srun_portal")
srun_portal_logout_api = parse.urljoin(login_url, "/cgi-bin/rad_user_dm")
srun_portal_info_api = parse.urljoin(login_url, "/cgi-bin/rad_user_info")

n = '200'
type = '1'
ac_id = '2'

enc = "srun_bx1"


def get_chksum(token, username, hmd5, ip, srbx1):
    chkstr = token+username
    chkstr += token+hmd5
    chkstr += token+ac_id
    chkstr += token+ip
    chkstr += token+n
    chkstr += token+type
    chkstr += token+srbx1
    return chkstr


def get_info(username, password, ip):
    info_temp = {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": ac_id,
        "enc_ver": enc
    }
    i = re.sub("'", '"', str(info_temp))
    i = re.sub(" ", '', i)
    return i


def init_getip():
    init_res = requests.get(login_url, headers=header)
    if init_res.status_code == 200:
        try:
            ip = re.search('id="user_ip" value="(.*?)"',
                           init_res.text).group(1)
            return ip
        except Exception:
            print(
                "Error parsing response data, you may need to change the login_url or the script may not suit your version!")
            sys.exit()
    else:
        print("Connect Timeout! Check your Internet connection!")
        sys.exit()


def get_token(username, ip):
    get_challenge_params = {
        "callback": "jQuery112404953340710317169_"+str(int(time.time()*1000)),
        "username": username,
        "ip": ip,
        "_": int(time.time()*1000),
    }
    get_challenge_res = requests.get(
        get_challenge_api, params=get_challenge_params, headers=header)
    if get_challenge_res.status_code == 200:
        token = re.search('"challenge":"(.*?)"',
                          get_challenge_res.text).group(1)
        return token
    else:
        print("Connect Timeout! Check your Internet connection!")
        sys.exit()


def do_encrypt_work(username, password, token, ip):
    srbx1 = get_info(username, password, ip)
    srbx1 = "{SRBX1}"+get_base64(get_xencode(srbx1, token))
    hmd5 = get_md5(password, token)
    chksum = get_sha1(get_chksum(token, username, hmd5, ip, srbx1))
    return srbx1, hmd5, chksum


def login(username, password):
    print("Login...")
    if get_login_info():
        print("You are already online! Logging out your current account...")
        logout()
    ip = init_getip()
    if ip:
        token = get_token(username, ip)
        if token:
            srbx1, hmd5, chksum = do_encrypt_work(
                username, password, token, ip)
            srun_portal_params = {
                'callback': 'jQuery11240645308969735664_'+str(int(time.time()*1000)),
                'action': 'login',
                'username': username,
                'password': '{MD5}'+hmd5,
                'ac_id': ac_id,
                'ip': ip,
                'chksum': chksum,
                'info': srbx1,
                'n': n,
                'type': type,
                'os': 'Windows 10',
                'name': 'Windows',
                'double_stack': '0',
                '_': int(time.time()*1000)
            }
            srun_portal_res = requests.get(
                srun_portal_login_api, params=srun_portal_params, headers=header)
            if srun_portal_res.status_code == 200:
                try:
                    if re.search('"error":"(.*?)"', srun_portal_res.text).group(1) == "ok":
                        print("Login Success!")
                        time.sleep(1)
                        show_login_info()
                    else:
                        try:
                            print("Login Failed"+"! "+return_code_en_US[re.search(
                                '"error_msg":"(.*?)"', srun_portal_res.text).group(1)]+".")
                        except Exception:
                            message = re.search(
                                '"error_msg":"(.*?)"', srun_portal_res.text)
                            if message:
                                print("Login Failed"+"! "+message.group(1))
                            else:
                                print(
                                    "Login Failed"+"! "+re.search('"error":"(.*?)"', srun_portal_res.text).group(1))
                except Exception:
                    print(
                        "Error parsing response data, you may need to change the login_url or the script may not suit your version!")
                    sys.exit()
            else:
                print("Connect Timeout! Check your Internet connection!")


'''
 For Get Logging Info
'''


def get_login_info():
    srun_portal_params = {
        'callback': 'jQuery112403468157183476275_'+str(int(time.time()*1000)),
        '_': int(time.time()*1000)
    }
    try:
        srun_portal_res = requests.get(
            srun_portal_info_api, params=srun_portal_params, headers=header)
    except Exception:
        print("You are not connected! Check your Internet connection!")
        sys.exit()
    if srun_portal_res.status_code == 200:
        try:
            if re.search('"error":"(.*?)"', srun_portal_res.text).group(1) == "ok":
                user_name = re.search(
                    '"user_name":"(.*?)"', srun_portal_res.text).group(1)
                user_mac = re.search('"user_mac":"(.*?)"',
                                     srun_portal_res.text).group(1)
                online_ip = re.search(
                    '"online_ip":"(.*?)"', srun_portal_res.text).group(1)
                sum_bytes = re.search(
                    '"sum_bytes":(.*?),', srun_portal_res.text).group(1)
                sum_seconds = re.search(
                    '"sum_seconds":(.*?),', srun_portal_res.text).group(1)
                user_balance = re.search(
                    '"user_balance":(.*?),', srun_portal_res.text).group(1)
                return user_name, user_mac, online_ip, sum_bytes, sum_seconds, user_balance
        except Exception:
            print("Error parsing response data, you may need to change the login_url or the script may not suit your version!")
            sys.exit()
        return None
    else:
        print("Connect Timeout! Check your Internet connection!")
        sys.exit()


def auto_bytes(bytes):
    if bytes < 1024:
        bytes = str(round(bytes, 2)) + ' B'
    elif bytes >= 1024 and bytes < 1024 * 1024:
        bytes = str(round(bytes / 1024, 2)) + ' KB'
    elif bytes >= 1024 * 1024 and bytes < 1024 * 1024 * 1024:
        bytes = str(round(bytes / 1024 / 1024, 2)) + ' MB'
    elif bytes >= 1024 * 1024 * 1024 and bytes < 1024 * 1024 * 1024 * 1024:
        bytes = str(round(bytes / 1024 / 1024 / 1024, 2)) + ' GB'
    elif bytes >= 1024 * 1024 * 1024 * 1024 and bytes < 1024 * 1024 * 1024 * 1024 * 1024:
        bytes = str(round(bytes / 1024 / 1024 / 1024 / 1024, 2)) + ' TB'
    elif bytes >= 1024 * 1024 * 1024 * 1024 * 1024 and bytes < 1024 * 1024 * 1024 * 1024 * 1024 * 1024:
        bytes = str(round(bytes / 1024 / 1024 / 1024 / 1024 / 1024, 2)) + ' PB'
    elif bytes >= 1024 * 1024 * 1024 * 1024 * 1024 * 1024 and bytes < 1024 * 1024 * 1024 * 1024 * 1024 * 1024 * 1024:
        bytes = str(round(bytes / 1024 / 1024 / 1024 /
                          1024 / 1024 / 1024, 2)) + ' EB'
    return bytes


def show_login_info():
    info = get_login_info()
    if info:
        print("")
        print("User Name:         "+info[0])
        print("Used Data:         "+auto_bytes(int(info[3])))
        seconds = int(info[4])
        m, s = divmod(seconds, 60)
        h, m = divmod(m, 60)
        print("Used Time:         %d:%02d:%02d" % (h, m, s))
        print("Account Balance:   "+info[5])
        print("IP:                "+info[2])
        print("MAC:               "+info[1])
    else:
        print("Show Login Info Failed! You are not connected or no account online!")


'''
 For Logout
'''

form_time = str(int(time.time()*10))
unbind = '1'


def get_sign(username, ip, unbind):
    return get_sha1(form_time + username + ip + unbind + form_time)


def logout():
    print("Logout...")
    info = get_login_info()
    if info:
        username = info[0]
        ip = info[2]
        sign = get_sign(username, ip, unbind)
        srun_portal_params = {
            'callback': 'jQuery1124042763452432355953_'+str(int(time.time()*1000)),
            'ip': ip,
            'username': username,
            'time': form_time,
            'unbind': unbind,
            'sign': sign,
            '_': int(time.time()*1000)
        }
        srun_portal_res = requests.get(
            srun_portal_logout_api, params=srun_portal_params, headers=header)
        if srun_portal_res.status_code == 200:
            try:
                if re.search('"error":"(.*?)"', srun_portal_res.text).group(1) == "logout_ok":
                    print("Logout Success!")
                else:
                    try:
                        print("Logout Failed! "+return_code_en_US[re.search(
                            '"error_msg":"(.*?)"', srun_portal_res.text).group(1)]+".")
                    except Exception:
                        message = re.search(
                            '"error_msg":"(.*?)"', srun_portal_res.text)
                    if message:
                        print("Logout Failed"+"! "+message.group(1))
                    else:
                        print("Logout Failed"+"! "+re.search('"error":"(.*?)"',
                                                             srun_portal_res.text).group(1))
            except Exception:
                print(
                    "Error parsing response data, you may need to change the login_url or the script may not suit your version!")
                sys.exit()
        else:
            print("Connect Timeout! Check your Internet connection!")
    else:
        print("Logout Failed! Not online!")


def show_help():
    print("")
    print("Usage:")
    print("--help     or -h to show this info.")
    print("--loginurl or -l to specify login_url.")
    print("--action   or -a to specify action.")
    print("         info   to show current loggin infomation.")
    print("         logout to logout current account.")
    print("         login  to login with specified information.")
    print("--username or -u to specify User Name.")
    print("--password or -p to specify Password.")
    print("")
    print("Examples:")
    print(
        "'-a login [-u username [ -p password]]'    to login with specified information.")
    print("'-a logout -l 10.10.0.166'                 to logout current account with specified login_url.")
    print("'<empty>'                                  to show current loggin infomation.")
    print("")


if __name__ == '__main__':
    action = "info"
    username = ""
    passwd = ""
    if len(sys.argv) == 1:
        show_login_info()
        sys.exit()
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hl:a:u:p:", [
                                   "help", "loginurl", "action", "username", "password"])
    except getopt.GetoptError:
        print("Unrecognized Parameter exists.")
        show_help()
        sys.exit()
    for o, a in opts:
        if o in ("-h", "--help"):
            show_help()
            sys.exit()
        elif o in ("-l", "--loginurl"):
            login_url = a
            if not login_url.startswith("http://") or not login_url.startswith("https://"):
                login_url = "http://" + login_url
            get_challenge_api = parse.urljoin(
                login_url, "/cgi-bin/get_challenge")
            srun_portal_login_api = parse.urljoin(
                login_url, "/cgi-bin/srun_portal")
            srun_portal_logout_api = parse.urljoin(
                login_url, "/cgi-bin/rad_user_dm")
            srun_portal_info_api = parse.urljoin(
                login_url, "/cgi-bin/rad_user_info")
        elif o in ("-a", "--action"):
            action = a
        elif o in ("-u", "--username"):
            username = a
        elif o in ("-p", "--password"):
            passwd = a

    if action == "info":
        show_login_info()
    elif action == "logout":
        logout()
    elif action == "login":
        if not username:
            username = input("Please input your user name:")
        if not passwd:
            passwd = getpass.getpass("Please input your password:")
        login(username, passwd)
