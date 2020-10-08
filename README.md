# 兰大深澜网络认证工具

[![last-commit](https://img.shields.io/github/last-commit/HollowMan6/Srun-LZU-Network-Auth)](../../graphs/commit-activity)
[![release-date](https://img.shields.io/github/release-date/HollowMan6/Srun-LZU-Network-Auth)](../../releases)
![Python package](https://github.com/HollowMan6/Srun-LZU-Network-Auth/workflows/Python%20package/badge.svg)

[![Followers](https://img.shields.io/github/followers/HollowMan6?style=social)](https://github.com/HollowMan6?tab=followers)
[![watchers](https://img.shields.io/github/watchers/HollowMan6/Srun-LZU-Network-Auth?style=social)](../../watchers)
[![stars](https://img.shields.io/github/stars/HollowMan6/Srun-LZU-Network-Auth?style=social)](../../stargazers)
[![forks](https://img.shields.io/github/forks/HollowMan6/Srun-LZU-Network-Auth?style=social)](../../network/members)

[![Open Source Love](https://img.shields.io/badge/-%E2%9D%A4%20Open%20Source-Green?style=flat-square&logo=Github&logoColor=white&link=https://hollowman6.github.io/fund.html)](https://hollowman6.github.io/fund.html)
[![GPL Licence](https://img.shields.io/badge/license-GPL-blue)](https://opensource.org/licenses/GPL-3.0/)
[![Repo-Size](https://img.shields.io/github/repo-size/HollowMan6/Srun-LZU-Network-Auth.svg)](../../archive/master.zip)

[![Total alerts](https://img.shields.io/lgtm/alerts/g/HollowMan6/Srun-LZU-Network-Auth.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/HollowMan6/Srun-LZU-Network-Auth/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/HollowMan6/Srun-LZU-Network-Auth.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/HollowMan6/Srun-LZU-Network-Auth/context:python)

(English version is down below)

[Python库依赖](../../network/dependencies)

[程序](slna.py)

Python版兰大深澜网络认证CLI登录、注销、查询信息客户端。

目前支持`SRun CGI Auth Intf Svr V1.18 B20200522`，可能并不局限于兰州大学（当然要更改代码中`login_url`变量值），也可能向前向后版本都会兼容。请多多尝试！

**使用方法**:

`login [用户名 [, 密码]]`    来使用指定信息登录。

`logout`                    来退出当前登录。

`<empty>`                   来显示当前登录账户信息。

# Srun LZU Network Auth

[Python Dependencies](../../network/dependencies)

[Programme](slna.py)

Tool for CLI login, logout, check acccount info for LZU 'SRun CGI Auth Intf Svr V1.18' using Python.

Currently, `SRun CGI Auth Intf Svr V1.18 B20200522` is supported. The programme may not be limited to Lanzhou University (of course, the variable value in the code `login_url` should be changed), may also be compatible with both newer and older versions. Please give it a try!

**Usage**:

`login [username [, password]]`    to login with specified information.

`logout`                           to logout current account.

`<empty>`                          to show current loggin infomation.

