import json
from json.decoder import JSONDecodeError
import subprocess
import os
import socket
import logging.handlers
import inspect
import traceback
import base64
import chardet
import binascii
import configparser
import requests
import warnings
import hashlib
import mmh3
from dark_log import DarkLog
from print_color import Colorpr
import operator
import ssl
import socket
import socks

# 禁用 InsecureRequestWarning
from urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter('ignore', InsecureRequestWarning)


def get_config(value_name):
    """
    获取配置文件中的指定值。

    参数:
        value_name (str): 需要获取的字段名。

    返回:
        str: 对应字段的值。如果未找到或为空，则退出程序。
    """
    ret_data = None
    config = configparser.ConfigParser()
    config.read('config.ini')
    sections = config.sections()
    for section in sections:  # 循环遍历所有section
        options = config.options(section)
        for option in options:  # 循环遍历每个section下的option
            value = config.get(section, option)
            if value_name == option:
                ret_data = value
    if ret_data is None or ret_data == "":
        exit(0)  # 如果未找到或为空，退出程序
    return ret_data


def encoded(encoded_data):
    """
    解码特定格式编码的数据。

    参数:
        encoded_data (str/dict/list): 编码后的数据字符串、字典或列表。

    返回:
        str/bytes/dict/list: 解码后的数据。如果不是特定格式，则返回原始数据。
    """
    if isinstance(encoded_data, (dict, list)):  # 如果是字典或列表，直接返回
        return encoded_data
    elif isinstance(encoded_data, str):  # 如果是字符串，进行解码处理
        if encoded_data.startswith("b64de|"):
            encoded_part = encoded_data[len("b64de|"):]
            decoded_data = base64.b64decode(encoded_part).decode('utf-8')
            return decoded_data
        elif encoded_data.startswith("hex|"):
            encoded_part = encoded_data[len("hex|"):]
            decoded_data = bytes.fromhex(encoded_part)
            return decoded_data
        else:
            return encoded_data
    else:
        return encoded_data  # 其他类型直接返回


def exec_jarm(ip, port):
    """
    执行 JARM 指纹识别命令并处理结果。

    参数:
        ip (str): 目标IP地址。
        port (int): 目标端口号。

    返回:
        dict: 包含状态码和数据的结果字典。
    """
    tlsx_exe = get_config('tlsx_exe')
    command = [
        tlsx_exe,
        "-u", f"{ip}:{port}",
        "-jarm",
        "-j",
        "-o", "tmp/tlsx_result.json",
        "-silent"
    ]
    command_exec = "Running command: " + " ".join(command)
    # print(Colorpr.color_red_bd(command_exec))
    DarkLog().logger.info(command_exec)
    with subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ,
            encoding='utf-8'
    ) as process:
        stdout, stderr = process.communicate()
        process.kill()
        formatted_output_stderr = ""
        formatted_output_stdout = ""
        if stderr:
            formatted_output_stderr = "\n\t".join(["\t|   " + line for line in stderr.strip().splitlines()])
            lines = stderr.split('\n')
            new_lines = [f"\t|  {line}" for line in lines if line]
            new_stderr = '\n'.join(new_lines)
        if stdout:
            formatted_output_stdout = "\n\t".join(["\t|   " + line for line in stdout.strip().splitlines()])
            lines = stdout.split('\n')
            new_lines = [f"\t|  {line}" for line in lines if line]
            new_stderr = '\n'.join(new_lines)
        if formatted_output_stderr:
            DarkLog().logger.info(
                'stdout: ⬇' + '\n\t' + formatted_output_stderr + '\n\t' + formatted_output_stdout + '\n')  # 日志记录
        return_code = process.wait()
        if return_code == 0:
            with open("tmp/tlsx_result.json", "r", encoding='utf-8') as f:
                try:
                    tlsx_json = json.loads(f.read())
                except JSONDecodeError as e:
                    tlsx_json = {}
                if len(tlsx_json) == 0:
                    return {"code": 501, "data": "[-] No results found"}
                else:
                    return {"code": 200, "data": tlsx_json['jarm_hash']}
        else:
            DarkLog().logger.warning({"code": 500, "data": "return_code is not 0"})
            return {"code": 500, "data": "return_code is not 0"}


class TCPc2:
    def __init__(self):
        """
        初始化TCP连接类。
        """
        self.condition_and = []
        self.condition_or = []
        self.matched_and = False

    def condition_def(self, name_condition, name_type, name_tf):
        """
        定义条件逻辑。

        参数:
            name_condition (str): 条件类型（'and' 或 'or'）。
            name_type (str): 条件匹配类型。
            name_tf (bool): 条件匹配结果。
        """
        if name_condition == 'and':
            self.condition_and.append({'type_': name_type, 'data': name_tf})
        else:
            self.condition_or.append({'type_': name_type, 'data': name_tf})

    def main(self, ip, port, packet, proxy):
        """
        发送TCP请求并处理响应。

        参数:
            ip (str): 目标IP地址。
            port (int): 目标端口号。
            packet (list): 请求包列表。
            proxy : socks5代理

        返回:
            self.matched_and bool 当前表达式是否匹配
            print_list_http 需要打印的字符
            {"is_successful": self.matched_and, "agreement": 'http', "data": print_list_http}
        """
        print_list_tcp = []
        relation_ops = {
            'eq': operator.eq,  # 等于
            'ne': operator.ne,  # 不等于
            'gt': operator.gt,  # 大于
            'lt': operator.lt,  # 小于
            'ge': operator.ge,  # 大于等于
            'le': operator.le  # 小于等于
        }
        if proxy:
            # 设置 SOCKS5 代理
            if proxy.startswith('socks5://'):
                # 去掉 "socks5://" 前缀
                address_part = proxy[len('socks5://'):]

                # 按 ":" 分割，获取 IP 和端口
                ip_proxy, port_proxy = address_part.split(':')

                # 设置全局 SOCKS5 代理
                socks.set_default_proxy(socks.HTTP, ip_proxy, int(port_proxy))
                socket.socket = socks.socksocket  # 替换默认的 socket 类
            elif proxy.startswith('http://'):
                # 去掉 "socks5://" 前缀
                address_part = proxy[len('http://'):]

                # 按 ":" 分割，获取 IP 和端口
                ip_proxy, port_proxy = address_part.split(':')
                socks.set_default_proxy(socks.HTTP, ip_proxy, int(port_proxy))
                socket.socket = socks.socksocket  # 替换默认的 socket 类
            else:
                print(Colorpr.color_blue_bd("socks5://ip:port or http://ip:port"))
                exit(0)
        for i in packet:
            type_ = i.get('type', '')
            words = i.get('words', '')
            send_data = i.get('send_data', '')
            condition = i.get('condition', 'or')
            relationship = i.get('relationship', "ge")
            method = i.get('method', '')
            op_func = relation_ops.get(relationship, operator.eq)
            try:
                with socket.create_connection((ip, int(port)), timeout=3) as sock:
                    sock.settimeout(8)
                    if method == 'ssl':  # 判断是否为SSL
                        context = ssl.create_default_context()
                        context.check_hostname = False  # 禁用主机名检查
                        context.verify_mode = ssl.CERT_NONE  # 禁用证书验证
                        with context.wrap_socket(sock, server_hostname=ip) as ssock:
                            if send_data is not None:
                                data_to_send = bytes.fromhex(encoded(send_data))
                                ssock.sendall(data_to_send)
                            response = ssock.recv(9024)  # 接收所有数据
                    else:  # TCP
                        if send_data is not None:
                            data_to_send = bytes.fromhex(encoded(send_data))
                            sock.sendall(data_to_send)
                        response = sock.recv(9024)  # 接收所有数据
                    #print(response)
                    #print(len(response))
                    if type_ == 'length':
                        for word in words:
                            # if len(response) >= int(word):
                            if op_func(len(response), int(word)):
                                # print(Colorpr.color_red_bd(f"listening port : {ip}:{port}"))
                                print_list_tcp.append(f"length: {word}")
                                self.condition_def(condition, type_, True)
                                break
                            else:
                                self.condition_def(condition, type_, False)
                    else:
                        for word in words:

                            if encoded(word) in response:
                                print_list_tcp.append(f"keyword: {encoded(word)}")
                                self.condition_def(condition, type_, True)
                                break
                            else:
                                self.condition_def(condition, type_, False)
            except socket.timeout:
                self.condition_def(condition, type_, False)
            except Exception as e:
                # print(e)
                # DarkLog().logger.warning(e)
                # DarkLog().logger.warning(DarkLog.get_error_())
                self.condition_def(condition, type_, False)
        for i in self.condition_and:
            if i['data'] is False:
                self.matched_and = False
                break
            else:
                self.matched_and = True
        for i in self.condition_or:
            if i['data'] is False:
                pass
            else:
                self.matched_and = True
                break
        return {"is_successful": self.matched_and, "agreement": 'tcp', "data": print_list_tcp}


class HTTPc2:
    def __init__(self):
        """
        初始化HTTP连接类。
        """
        self.condition_and = []
        self.condition_or = []
        self.matched_and = False

    def condition_def(self, name_condition, name_type, name_tf):
        """
        定义条件逻辑。

        参数:
            name_condition (str): 条件类型（'and' 或 'or'）。
            name_type (str): 条件匹配类型。
            name_tf (bool): 条件匹配结果。
        """
        if name_condition == 'and':
            self.condition_and.append({'type_': name_type, 'data': name_tf})
        else:
            self.condition_or.append({'type_': name_type, 'data': name_tf})

    def main(self, url, packet, proxy):
        """
        发送HTTP请求并处理响应。

        参数:
            url (str): 请求URL。
            packet (list): 请求包列表。

        返回:
            self.matched_and bool 当前表达式是否匹配
            print_list_http 需要打印的字符
            {"is_successful": self.matched_and, "agreement": 'http', "data": print_list_http}
        """
        relation_ops = {
            'eq': operator.eq,  # 等于
            'ne': operator.ne,  # 不等于
            'gt': operator.gt,  # 大于
            'lt': operator.lt,  # 小于
            'ge': operator.ge,  # 大于等于
            'le': operator.le  # 小于等于
        }
        print_list_http = []
        proxies = {}
        if proxy:
            if proxy.startswith('socks5://') or proxy.startswith('http://'):
                proxies = {
                    'http': proxy,
                    'https': proxy
                }
            else:
                print(Colorpr.color_blue_bd("socks5://ip:port or http://ip:port"))
                exit(0)
        for i in packet:
            method = i.get('method', '')
            type_ = i.get('type', '')
            words = i.get('words', '')
            send_data = i.get('send_data', '')
            path = i.get('path', '')
            condition = i.get('condition', 'or')
            send_data_type = i.get('send_data_type', '')
            relationship = i.get('relationship', "ge")  # 默认关系为大于等于
            try:
                url_ = url
                if path is not None:
                    if url.endswith('/'):
                        url_ = url[:-1] + encoded(path)
                    else:
                        url_ = url + encoded(path)

                if method == 'POST':
                    if send_data_type == 'json':
                        data = requests.post(url_, verify=False, proxies=proxies, json=encoded(send_data), timeout=8)
                    else:
                        data = requests.post(url_, verify=False, proxies=proxies, data=encoded(send_data), timeout=8)
                elif method == 'OPTIONS':
                    data = requests.options(url_, verify=False, proxies=proxies, timeout=8)
                else:
                    data = requests.get(url_, verify=False, proxies=proxies, timeout=8)
                data.encoding = data.apparent_encoding  # 获取编码，不然中文乱码
                if type_ == 'body':

                    if send_data_type == 'json':
                        data_txt = data.json()
                    else:
                        data_txt = data.text
                    for word in words:

                        if send_data_type == 'json':
                            is_data = (word == data_txt)  # 匹配json
                        else:
                            is_data = (word in data_txt)  # 匹配字符

                        if is_data:  # 判断是否能匹配成功
                            self.condition_def(condition, type_, True)
                            # print(Colorpr.color_red_bd(f"body: {word}"))
                            print_list_http.append(f"body: {word}")
                            break
                        else:
                            self.condition_def(condition, type_, False)
                elif type_ == 'response_header':
                    matched = False
                    data_headers = data.headers.items()
                    headers_as_strings = [f"{key}: {value}" for key, value in data.headers.items()]

                    for key, value in data_headers:
                        for word in words:
                            if word in headers_as_strings:  # 匹配整个
                                # print(Colorpr.color_red_bd(f"response header: {word}"))
                                matched = True
                                print_list_http.append(f"response header: {word}")
                                break
                            if word in key or word in value:  # 匹配单个
                                # print(Colorpr.color_red_bd(f"response header: {word}"))
                                matched = True
                                print_list_http.append(f"response header: {word}")
                                break
                    if matched:
                        self.condition_def(condition, type_, True)
                    else:
                        self.condition_def(condition, type_, False)
                elif type_ == 'status_code':
                    for word in words:
                        if int(word) == data.status_code:
                            self.condition_def(condition, type_, True)
                            print_list_http.append(f"status_code: {word}")
                            # print(Colorpr.color_red_bd(f"status_code: {word}"))
                            break
                        else:
                            self.condition_def(condition, type_, False)
                elif type_ == 'body_length':
                    data_txt = data.text
                    op_func = relation_ops.get(relationship, operator.eq)
                    for word in words:
                        if op_func(len(data_txt), int(word)):
                            # if int(word) < len(data.text):
                            self.condition_def(condition, type_, True)
                            print_list_http.append(f"body_length: {word}")
                            # print(Colorpr.color_red_bd(f"body_length: {word}"))
                            break
                        else:
                            self.condition_def(condition, type_, False)
                elif type_ == 'favicon':
                    md5_hash = hashlib.md5(data.content).hexdigest()
                    mmh3_hash = mmh3.hash(data.content)
                    for word in words:
                        if word == mmh3_hash or word == md5_hash:
                            self.condition_def(condition, type_, True)
                            # print(Colorpr.color_red_bd(f"favicon: {word}"))
                            print_list_http.append(f"favicon: {word}")
                            break
                        else:
                            self.condition_def(condition, type_, False)
            except Exception as e:
                # DarkLog().logger.warning(e)
                # DarkLog().logger.warning(DarkLog().get_error_())
                self.condition_def(condition, type_, False)

        for i_ in self.condition_and:
            if i_['data'] is False:
                self.matched_and = False
                break
            else:
                self.matched_and = True
        for i_ in self.condition_or:
            if i_['data'] is False:
                pass
            else:
                self.matched_and = True
                break

        return {"is_successful": self.matched_and, "agreement": 'http', "data": print_list_http}
