import requests
import configparser
import base64
import ssl
import socket
from dark_log import DarkLog
import ipaddress
from print_color import Colorpr
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import os

darklog = DarkLog()


class Cyberspace:
    """
    Cyberspace : 用于搜索引擎调用返回数据。
    """

    @staticmethod
    def get_config(value_name):
        """
        功能描述: 返回config.ini中配置文件对于值
        参数:
            value_name : 需要获取的字段名 [fofa_key]
        返回值:
        异常描述:
        调用演示:
            fofa = self.get_config('fofa')
        """
        ret_data = None
        config = configparser.ConfigParser()
        config.read('config.ini')
        sections = config.sections()
        for section in sections:  # 循环[n+1]
            options = config.options(section)
            for option in options:  # 循环详细的字段
                value = config.get(section, option)
                if value_name == option:
                    ret_data = value
        if ret_data is None or ret_data == "":
            ret_data = None
            # print(Colorpr().color_blue_bd(f"请配置{value_name}"))
            # exit(0)
        return ret_data

    @staticmethod
    def unique_list_(input_batch):
        """
        :param input_batch: 去重前的结果
        :return: unique_arr 去重后的结果
        """
        unique_arr = []

        if input_batch is not None and len(input_batch) > 0:
            unique_arr = []
            seen = set()
            # 过滤掉空字符串
            filtered_batch = [item for item in input_batch if item != '']
            for item in filtered_batch:
                if item not in seen:
                    unique_arr.append(item)
                    seen.add(item)
        return unique_arr

    @staticmethod
    def get_base64(value_b64encode=None, value_b64decode=None):
        """
        功能描述: 加密解密base64
        参数:
            value_b64encode : 加密
            value_b64decode : 解密
        返回值:
        异常描述:
        调用演示:
            fofa = self.get_config('fofa')
        """
        if value_b64encode is not None:
            # 进行Base64编码
            return base64.b64encode(value_b64encode.encode('utf-8')).decode('utf-8')
        elif value_b64decode is not None:
            # 进行Base64解密
            return base64.b64decode(value_b64decode).decode('utf-8')

    @staticmethod
    def get_ssl_certificate_details(hostname, port=443, timeout=5):
        """
        功能描述: 获取HTTPS网站的SSL证书中的证书持有者的组织信息、公用名和证书序列号
        参数:
            hostname : 主机名或IP地址
            port : 端口号 (默认: 443)
            timeout : 超时时间 (默认: 5秒)
        返回值:
            dict : 包含主机的组织信息、公用名和证书序列号 {
                "organization": "Beijing Baidu Netcom Science Technology Co., Ltd",
                "common_name": "baidu.com",
                "serial_number": "12345678901234567890"
            }
        """

        def fetch_certificate(hostname_):
            # 检查是否为IP地址
            is_domain_ = False
            try:
                ipaddress.ip_address(hostname_)
            except ValueError:
                is_domain_ = True

            # 创建SSL上下文
            context = ssl.create_default_context()
            if not is_domain_:
                # 如果是IP地址，禁用主机名检查
                context.check_hostname = False

            try:
                with socket.create_connection((hostname_, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname_ if is_domain_ else None) as ssock:
                        cert_ = ssock.getpeercert(binary_form=True)
                        x509_cert = ssl.DER_cert_to_PEM_cert(cert_)
                return x509_cert
            except ssl.SSLCertVerificationError:
                return None
            except Exception:
                return None

        def parse_certificate(cert):
            cert_obj = x509.load_pem_x509_certificate(cert.encode(), default_backend())
            # 获取证书序列号并返回十进制字符串
            serial_number_decimal = str(cert_obj.serial_number)
            return cert_obj.subject, serial_number_decimal

        # 检查是否为IP地址
        try:
            ipaddress.ip_address(hostname)
            is_domain = False
        except ValueError:
            is_domain = True

        # 初次尝试获取证书
        cert = fetch_certificate(hostname)
        # 如果失败并且是域名没有加 www，则尝试添加 www
        if not cert and is_domain and not hostname.startswith("www."):
            cert = fetch_certificate(f"www.{hostname}")
            if not cert:
                return None
            else:
                hostname = f"www.{hostname}"

        # 如果获取到证书，提取信息
        if cert:
            subject, serial_number_decimal = parse_certificate(cert)
            organization = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
            common_name = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)

            organization = organization[0].value if organization else "未知组织"
            common_name = common_name[0].value if common_name else "未知"

            return {
                "organization": organization,
                "common_name": common_name,
                "serial_number": serial_number_decimal
            }
        else:
            return None

    def get_cyberspace(self, ip=None, icp=None, domain=None, title=None, body=None, size=1000, proxy=None):
        """
        功能描述: 搜索语句集合搜索
        参数:
            ip : ip地址
            icp : 备案号   [京ICP证030173号]
            domain : 域名 [xxx.com]
            tls_san : 证书持有者的通用名称 [一般是域名](通过域名获取)
            tls_subject_ : 证书持有者的组织  (通过域名获取)
            title : 网站标题
            body : 网页内容
            siez: 默认一千数据
        返回
            {"code": 403, "data": None}  re_data 为空
            {"code": 200, "data": re_data} re_data 不为空 {"code": 200, "data": ["baidu.com","www.baidu.com"]}
        """
        re_data = []
        quake_data = []
        fofa_data = []
        proxies = {}
        if proxy:
            if proxy.startswith('socks5://') or proxy.startswith('http://'):
                proxies = {
                    "http": proxy,
                    "https": proxy
                }
            else:
                print(Colorpr.color_blue_bd("socks5://ip:port or http://ip:port"))
                exit(0)
        quake_key = self.get_config('quake_key')
        fofa_key = self.get_config('fofa_key')
        if quake_key is None and fofa_key is None:
            print(Colorpr.color_blue_bd("quake fofa key is Null"))
            darklog.logger.error("quake fofa key is Null")
            exit(0)

        if quake_key is not None:
            print(Colorpr.color_red_bd("quake - query"))
            darklog.logger.info({"code": 200, "data": "quake - query"})
            quake_data = self.get_quake(ip=ip, icp=icp, domain=domain, title=title, body=body, size=size,
                                        proxies=proxies)
            if quake_data['code'] == 200:
                re_data.extend(quake_data['data'])

        if fofa_key is not None:
            print(Colorpr.color_red_bd("fofa - query"))
            darklog.logger.info({"code": 200, "data": "fofa - query"})
            fofa_data = self.get_fofa(ip=ip, icp=icp, domain=domain, title=title, body=body, proxies=proxies)
            if fofa_data['code'] == 200:
                re_data.extend(fofa_data['data'])

        if len(re_data) == 0:
            darklog.logger.error({"code": 500, "data": [quake_data, fofa_data]})
            return {"code": 403, "data": None}
        else:
            unique_arr = []
            if re_data is not None and len(re_data) > 0:  # 去重
                unique_arr = []
                seen = set()
                # 过滤掉空字符串
                filtered_batch = [item for item in re_data if item != '']
                for item in filtered_batch:
                    if item not in seen:
                        unique_arr.append(item)
                        seen.add(item)
            darklog.logger.info(f"Cyberspace Resources: {len(unique_arr)}")
            return {"code": 200, "data": unique_arr}

    def get_quake(self, proxies, ip=None, icp=None, domain=None, tls_san=None, tls_subject_=None, title=None, body=None,
                  size=1000):
        """
        功能描述: quake语句搜索返回数据
        参数:
            ip : ip地址
            icp : 备案号   [京ICP证030173号]
            domain : 域名 [xxx.com]
            tls_san : 证书持有者的通用名称 [一般是域名](通过域名获取)
            tls_subject_ : 证书持有者的组织  (通过域名获取)
            title : 网站标题
            body : 网页内容
            size: 默认一千数据
        返回值:
            {"code": 403, "data": response.json()} 请求失败, 返回请求失败原因
            {"code": 200, "data": http_load_url} 返回测绘结果
            {"code": 500, "data": e}  代码出现错误
        """
        query = []
        query_json = ""
        quake_key = self.get_config('quake_key')

        if ip is not None:
            query.append(f'ip:"{ip}"')
        if icp is not None:
            query.append(f'icp:"{icp}"')
        if domain is not None:
            query.append(f'domain:"{domain}"')
        if title is not None:
            query.append(f'title:"{title}"')
        if body is not None:
            query.append(f'body:"{body}"')

        if tls_san is not None:  # 域名
            query.append(f'tls_SAN:"{tls_san}"')
        else:
            if domain is not None:
                cert_subject_cn = self.get_ssl_certificate_details(domain)
                if cert_subject_cn is not None:
                    common_name = cert_subject_cn['common_name'].replace('www.', '')
                    query.append(f'tls_SAN:"{common_name}"')
                    query.append(f'''tls_SN:"{cert_subject_cn['serial_number']}"''')  # 证书序列号
            elif ip is not None:
                cert_subject_cn = self.get_ssl_certificate_details(ip)
                if cert_subject_cn is not None:
                    common_name = cert_subject_cn['common_name'].replace('www.', '')
                    query.append(f'tls_SAN:"{common_name}"')
                    query.append(f'''tls_SN:"{cert_subject_cn['serial_number']}"''')  # 证书序列号

        if tls_subject_ is not None:  # 证书持有者的组织
            query.append(f'tls_subject_O: "{tls_subject_}"')
        else:
            if domain is not None:
                cert_ubject_org = self.get_ssl_certificate_details(domain)
                if cert_ubject_org is not None:
                    organization = cert_ubject_org['organization']
                    if organization != '未知组织':
                        query.append(f'tls_subject_O: "{organization}"')
                        query.append(f'''tls_SN:"{cert_ubject_org['serial_number']}"''')  # 证书序列号
            elif ip is not None:
                cert_ubject_org = self.get_ssl_certificate_details(ip)
                if cert_ubject_org is not None:
                    organization = cert_ubject_org['organization']
                    if organization != '未知组织':
                        query.append(f'tls_subject_O: "{organization}"')
                        query.append(f'''tls_SN:"{cert_ubject_org['serial_number']}"''')  # 证书序列号
        query = self.unique_list_(query)
        for qb in query:
            if qb != query[-1]:
                query_json = query_json + qb + ' OR '
            else:
                query_json = query_json + qb

        headers = {
            "X-QuakeToken": quake_key,
            "Content-Type": "application/json"
        }
        data = {
            "query": query_json,
            "start": 0,
            "size": size
        }
        try:
            quake_user = requests.get('https://quake.360.net/api/v3/user/info', headers=headers, proxies=proxies)
            if quake_user.json()['code'] != 0:
                darklog.logger.error({"code": 403, "data": quake_user.json()})
                return {"code": 403, "data": quake_user.json()}
            else:
                darklog.logger.info(f"quake user info: -> {quake_user.json()}")
            darklog.logger.info({"code": 200, "data": query_json})
            http_load_url = []
            response = requests.post(url="https://quake.360.net/api/v3/search/quake_service", headers=headers,
                                     json=data, proxies=proxies)
            if response.json()['code'] != 0:
                darklog.logger.error({"code": 403, "data": response.json()})
                return {"code": 403, "data": response.json()}
            for i in response.json()['data']:
                try:
                    for url in i['service']['http']['http_load_url']:
                        http_load_url.append(url)
                except KeyError:
                    pass
            darklog.logger.info({"code": 200, "data": query_json})  # 日志返回搜索引擎语句
            return {"code": 200, "data": http_load_url}  # 返回资产结果
        except Exception as e:
            darklog.logger.error({"code": 500, "data": e})
            return {"code": 500, "data": e}

    def get_fofa(self, proxies, ip=None, icp=None, domain=None, cert_subject_cn=None, cert_ubject_org=None, title=None,
                 body=None):
        """
        功能描述: fofa语句搜索返回数据
        参数:
            ip : ip地址
            icp : 备案号   [京ICP证030173号]
            domain : 域名 [xxx.com]
            cert_subject_cn : 证书持有者的通用名称 [一般是域名](通过域名获取)
            cert_ubject_org : 证书持有者的组织  (通过域名获取)
            title : 网站标题
            body : 网页内容
        返回值:
            {"code": 200, "data": data.json()['results']} 请求成功, 返回资产结果
            {"code": 403, "data": data.json()['errmsg']} fafa请求失败,返回fofa错误信息
            {"code": 500, "data": e}  代码出现错误
        日志:
            (f"fofa user info: -> {fofa_user_info}") fofa账户信息
            {"code": 200, "data": self.get_base64(value_b64decode=qbase64)} 请求成功, 返回资产搜索语法
            {"code": 200, "data": f"fofa next: {i}"}  翻页达到第几页
            {"code": 403, "data": data.json()['errmsg']} fafa请求失败,返回fofa错误信息
            {"code": 500, "data": e}  代码出现错误
        异常描述:
            200: 请求成功
            403: fofa请求错误
            500: 代码错误
        调用演示:
            cyberspace = Cyberspace().get_fofa(icp="沪ICP备xxxxxxx号-1", domain="xxxxxx.cn", cert_subject_cn="xxxxxxxxxxx.cn")
        """
        qbase = []
        qbase64 = ''
        fofa_key = self.get_config('fofa_key')
        if ip is not None:
            qbase.append(f'ip="{ip}"')
        if icp is not None:
            qbase.append(f'icp="{icp}"')
        if domain is not None:
            qbase.append(f'domain="{domain}"')
        if title is not None:
            qbase.append(f'title="{title}"')
        if body is not None:
            qbase.append(f'body="{body}"')

        if cert_subject_cn is not None:  # SSL域名
            qbase.append(f'cert.subject.cn="{cert_subject_cn}"')
        else:
            if domain is not None:
                cert_subject_cn = self.get_ssl_certificate_details(domain)
                if cert_subject_cn is not None:
                    common_name = cert_subject_cn['common_name'].replace('www.', '')
                    qbase.append(f'cert.subject.cn="{common_name}"')
                    qbase.append(f'''cert="{cert_subject_cn['serial_number']}"''')  # 证书序列号
                    qbase.append(f'host="{common_name}"')  # host信息
            elif ip is not None:
                cert_subject_cn = self.get_ssl_certificate_details(ip)
                if cert_subject_cn is not None:
                    common_name = cert_subject_cn['common_name'].replace('www.', '')
                    qbase.append(f'cert.subject.cn="{common_name}"')
                    qbase.append(f'''cert="{cert_subject_cn['serial_number']}"''')  # 证书序列号
                    qbase.append(f'host="{common_name}"')  # host信息

        if cert_ubject_org is not None:  # SSL组织
            qbase.append(f'cert.subject.org="{cert_ubject_org}"')
        else:
            if domain is not None:
                cert_ubject_org = self.get_ssl_certificate_details(domain)
                if cert_ubject_org is not None:
                    organization = cert_ubject_org['organization']
                    if organization != '未知组织':
                        qbase.append(f'cert.subject.org="{organization}"')
                        qbase.append(f'''cert="{cert_ubject_org['serial_number']}"''')  # 证书序列号
            elif ip is not None:
                cert_ubject_org = self.get_ssl_certificate_details(ip)
                if cert_ubject_org is not None:
                    organization = cert_ubject_org['organization']
                    if organization != '未知组织':
                        qbase.append(f'cert.subject.org="{organization}"')
                        qbase.append(f'''cert="{cert_ubject_org['serial_number']}"''')  # 证书序列号

        qbase = self.unique_list_(qbase)
        for qb in qbase:
            if qb != qbase[-1]:
                qbase64 = qbase64 + qb + ' || '
            else:
                qbase64 = qbase64 + qb

        # print(qbase64)
        qbase64_ = qbase64

        data_list = []
        try:
            fofa_user_info = requests.get(
                f'https://fofa.info/api/v1/info/my?key={fofa_key}', proxies=proxies).json()
            if fofa_user_info['error'] is not True:
                darklog.logger.info(f"fofa user info: -> {fofa_user_info}")
                i = 1
                while True:
                    qbase64 = qbase64_ + ' && ' + 'after="2024-01-01"'  # 筛选2024-01-01时间之后有更新的资产
                    qbase64 = self.get_base64(qbase64)
                    darklog.logger.info({"code": 200, "data": self.get_base64(value_b64decode=qbase64)})  # 日志返回搜索引擎语句
                    data = requests.get(
                        f"https://fofa.info/api/v1/search/all?&key={fofa_key}&qbase64={qbase64}&fields=link&page={i}&size=5000",
                        proxies=proxies)
                    if data.json()['error'] is not True:
                        data_list.extend(data.json()['results'])
                        i = i + 1
                    else:
                        darklog.logger.warning({"code": 200, "data": f"fofa next: {i}"})
                        break

                i = 1
                while True:
                    qbase64 = qbase64_ + ' && ' + 'before="2024-01-01"'  # 筛选2024-01-01时间之前有更新的资产
                    qbase64 = self.get_base64(qbase64)
                    darklog.logger.info({"code": 200, "data": self.get_base64(value_b64decode=qbase64)})  # 日志返回搜索引擎语句
                    data = requests.get(
                        f"https://fofa.info/api/v1/search/all?&key={fofa_key}&qbase64={qbase64}&fields=link&page={i}&size=5000",
                        proxies=proxies)
                    if data.json()['error'] is not True:
                        data_list.extend(data.json()['results'])
                        i = i + 1
                    else:
                        darklog.logger.warning({"code": 200, "data": f"fofa next: {i}"})
                        break

                return {"code": 200, "data": data_list}  # 返回资产结果
            else:
                darklog.logger.warning({"code": 403, "data": fofa_user_info})
        except Exception as e:
            darklog.logger.error({"code": 500, "data": e})
            darklog.logger.error(darklog.get_error_())
            print(Colorpr.color_blue_bd(e))
            return {"code": 500, "data": e}
