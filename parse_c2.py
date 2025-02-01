import requests
from transmitter_c2 import HTTPc2, TCPc2, exec_jarm
import yaml
from print_color import Colorpr
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dark_log import DarkLog
from pathlib import Path


def read_yaml(file_path):
    # 打开文件并读取 YAML 内容
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data_ = yaml.safe_load(file)  # 读取 YAML 文件并解析为 Python 对象
            return data_
    except Exception as e:
        print(Colorpr.color_blue_bd(f"YAML error: {e}"))
        DarkLog().logger.error(f"YAML error: {e}")
        DarkLog().logger.error(DarkLog().get_error_())
        exit(0)


def string_in_string_exact_match(source_string, target_string):
    """
    检查源字符串是否完全匹配目标字符串的所有子串（考虑逗号分隔），忽略顺序。

    :param source_string: 源字符串（以逗号分隔的子串）
    :param target_string: 目标字符串（以逗号分隔的子串）
    :return: 如果源字符串的子串完全匹配目标字符串的所有子串（忽略顺序），返回 True；否则返回 False
    """
    # 将两个字符串分割成子串列表并排序
    source_parts = sorted(source_string.split(","))
    target_parts = sorted(target_string.split(","))
    # 检查源字符串的子串是否完全与目标字符串的子串匹配（忽略顺序）
    return source_parts == target_parts


def handle_conditions(expression, conditions, value, judge, key_type):
    """
    根据表达式和条件更新 judge 字典（忽略顺序）。

    :param expression: 当前的表达式（例如 'tcp,http,jarm'）
    :param conditions: 包含判断条件的字典，例如 {'tcp,http,jarm': True, ...}
    :param value: 当前 YAML 条目
    :param judge: 存储最终判断结果的字典
    :param key_type: 当前处理的是 'IF' 还是 'ELSE'
    """
    for key, condition in conditions.items():
        if string_in_string_exact_match(expression, key) and condition:
            judge['TF'] = True
            judge['version'] = value.get(key_type, {}).get('version', '')
            judge['type'] = value.get(key_type, {}).get('type', '')
            return


def run_c2_main(ip, port, yaml_file_path, protocol, proxy):
    """
    :param proxy: socks5代理
    :param ip: ip 地址
    :param port: 端口
    :param yaml_file_path: yaml文件路径
    :param protocol: 判断协议，主要是判断http还是https
    :return: 错误{"is_successful": False}
             正确 {'id': 'vshell', 'version': '4.6.0~4.9.3', 'name': 'vshell', 'author': 'ruoji', 'tags': 'vshell', 'severity': 'critical', 'metadata': {'product': 'vshell', 'vendor': 'dbappsecurity', 'verified': True}, 'tcp_tf': {'is_successful': True, 'agreement': 'tcp', 'data': ['listening port : 192.168.65.164:2244']}, 'http_tf': {'is_successful': True, 'agreement': 'http', 'data': ['body: export PATH=$PATH:/bin:/usr/bin:/sbin:/usr/local/bin:/usr/sbin']}, 'is_successful': True}
             {'jarm_hash': ['jarm 192.168.65.164:50050 -> CS_4.9.1_星落安全团队'], 'id': 'CS', 'name': 'CS', 'author': 'ruoji', 'tags': 'CS', 'severity': 'critical', 'metadata': {'product': 'CS', 'vendor': 'CS', 'verified': True}, 'query': {'fofa': None, 'quake': None, 'shodan': None, 'hunter': None, 'zoomeye': None}, 'tcp_tf': {'is_successful': False}, 'http_tf': {'is_successful': False, 'agreement': 'http', 'data': []}, 'is_successful': True}

    """
    httpc2 = HTTPc2()
    tcp2 = TCPc2()
    http_tf = {
        'is_successful': False}  # 接收返回值 {"is_successful": self.matched_and, "agreement": 'http', "data": print_list_http}
    tcp_tf = {
        'is_successful': False}  # 接收返回值 {"is_successful": self.matched_and, "agreement": 'tcp', "data": print_list_http}
    yaml_data = read_yaml(yaml_file_path)

    jarm_hash_list = []
    default = True  # 控制jarm_hash中的default，如果default复制了，就不对比其它jarm
    if proxy is None:  # tlsx工具不支持代理，如果设置了代理则跳过检测
        for key, value in yaml_data.items():
            if key == "jarm_hash":
                for key2, value2 in value.items():
                    jarm_hash = exec_jarm(ip, port)
                    for key3, value3 in value2.items():
                        for value_list in value3:
                            if jarm_hash['code'] == 200 and jarm_hash['data'] == value_list:
                                if key2 == "default":
                                    jarm_hash_list.append(f"{key3}")
                                    default = None
                                elif default and key2 == "login":
                                    jarm_hash_list.append(f"{key3}")
                                elif default and key2 == "l_port":
                                    jarm_hash_list.append(f"{key3}")
    for key, value in yaml_data.items():
        if "packet" == key:
            for key2, value2 in value.items():
                if key2 == "http":
                    if protocol == 'http':
                        http_tf = httpc2.main(f'http://{ip}:{port}/', value2,
                                              proxy)  # 注意需要修改https，根据gogo获取来选择是http还是https
                    else:
                        http_tf = httpc2.main(f'https://{ip}:{port}/', value2, proxy)
                if key2 == "tcp":
                    tcp_tf = tcp2.main(ip, port, value2, proxy)

    if http_tf["is_successful"]:
        DarkLog().logger.info(http_tf)
    if tcp_tf["is_successful"]:
        DarkLog().logger.info(tcp_tf)
    if len(jarm_hash_list) > 0:
        DarkLog().logger.info(jarm_hash_list)
    """
    根据 HTTP、TCP 和 JARM 条件处理判断逻辑。

    :param yaml_data: YAML 数据
    :param http_tf: HTTP 测试结果
    :param tcp_tf: TCP 测试结果
    :param jarm_hash_list: JARM 哈希列表
    :return: 处理后的 judge 字典
    """
    judge = {'TF': False}

    # 确定是否需要判断
    if http_tf['is_successful'] or tcp_tf['is_successful'] or len(jarm_hash_list) != 0:
        for key, value in yaml_data.items():
            if key == "judge":
                conditions = {
                    'tcp,http,jarm': http_tf['is_successful'] and tcp_tf['is_successful'] and len(jarm_hash_list) != 0,
                    'tcp,http': http_tf['is_successful'] and tcp_tf['is_successful'],
                    'tcp,jarm': tcp_tf['is_successful'] and len(jarm_hash_list) != 0,
                    'http,jarm': http_tf['is_successful'] and len(jarm_hash_list) != 0,
                    'tcp': tcp_tf['is_successful'],
                    'http': http_tf['is_successful'],
                    'jarm': len(jarm_hash_list) != 0,
                }

                # 处理 IF 表达式
                if 'IF' in value:
                    handle_conditions(value['IF']['expression'], conditions, value, judge, 'IF')

                # 如果未通过 IF 判断，处理 ELSE 表达式
                if not judge['TF'] and 'ELSE' in value:
                    handle_conditions(value['ELSE']['expression'], conditions, value, judge, 'ELSE')

    """
    根据条件创建返回列表。

    :param jarm_hash_list: jarm 的 hash 列表
    :param judge: 判断结果字典
    :param yaml_data: YAML 数据字典
    :param tcp_tf: TCP 测试结果
    :param http_tf: HTTP 测试结果
    :return: 构造的返回列表字典
    """
    return_list = {
        "jarm_hash": jarm_hash_list if jarm_hash_list else [],
        "is_successful": False,  # 默认值
    }

    # 如果条件匹配
    if judge['TF']:
        return_list["id"] = yaml_data.get("id") or ""
        return_list["version"] = judge.get("version") or ""
        return_list["type"] = judge.get("type") or ""

        # 添加 info 信息
        if "info" in yaml_data:
            return_list.update(yaml_data["info"])

        # 添加传输协议测试结果
        return_list["tcp_tf"] = tcp_tf
        return_list["http_tf"] = http_tf

        # 如果至少满足一项条件，设置 is_successful 为 True
        return_list["is_successful"] = True

    return return_list


def list_all_files():
    directory = 'server_fingerprint/yaml'
    yaml_files = []
    try:
        # 遍历目录及其子目录
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.yaml') or file.endswith('.yml'):
                    # 获取文件的完整路径
                    full_path = os.path.join(root, file)
                    yaml_files.append(full_path)
        return yaml_files
    except FileNotFoundError:
        print(Colorpr.color_blue_bd(f"The directory '{directory}' does not exist."))
        DarkLog().logger.error(f"The directory '{directory}' does not exist.")
        exit(0)
    except Exception as e:
        print(Colorpr.color_blue_bd(f"An error occurred: {e}"))
        DarkLog().logger.error(f"An error occurred: {e}")
        DarkLog().logger.error(DarkLog().get_error_())
        exit(0)


class C2run:
    def main(self, ip, port, protocol, proxy, file_yaml, tags):

        file_names = []
        file_path_yaml = []

        # 检查 file_yaml 是否符合 .yaml 或 .yml 后缀
        if file_yaml and not (file_yaml.endswith('.yaml') or file_yaml.endswith('.yml')):
            print(Colorpr.color_blue_bd("No file yaml"))  # 如果不符合，打印错误信息
            return {'is_successful': False}

        # 判断获取那个yaml文件，是默认的还是指定的yaml
        if file_yaml:
            file_names.append(file_yaml)
        else:
            file_names = list_all_files()
        # 如果 tages 参数不为空，筛选符合条件的文件
        if tags:
            # 检查 tages 是否是英文逗号分隔
            if not all(c.isalnum() or c == '-' for tag in tags.split(',') for c in tag.strip()):
                print(Colorpr.color_blue_bd("Invalid tages format. Expected comma-separated alphanumeric tags."))
                return {'is_successful': False}

            # 将 tages 转换为集合
            tags_set = {tag.strip().lower() for tag in tags.split(',') if tag.strip()}  # 去空，转大小写，存储为list
            for file_name in file_names:
                yaml_data = read_yaml(file_name)
                file_tags = {tag.strip().lower() for tag in yaml_data.get('info', {}).get('tags', '').split(',') if
                             tag.strip()}
                if tags_set.intersection(file_tags):
                    # 判断输入的tags在指定的yaml文件中是否存在
                    file_path_yaml.append(file_name)
                    DarkLog().logger.info('tags: ' + ','.join(file_tags))
                    DarkLog().logger.info(file_path_yaml)
        else:  # 如果tages为空直接扫描file_names
            file_path_yaml = file_names

        # 如果没有符合条件的文件
        if not file_path_yaml:
            print(Colorpr.color_blue_bd("No files match the specified tags."))
            return {'is_successful': False}
        result_list = []
        results_re = {
            'is_successful': False
        }
        # 使用线程池执行任务
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {
                executor.submit(
                    run_c2_main,  # 目标函数
                    ip,  # IP 参数
                    port,  # 端口参数
                    file_name,  # 直接使用 file_path_yaml 地址
                    protocol,  # 协议参数
                    proxy  # 代理参数
                ): file_name
                for file_name in file_path_yaml
            }

            for future in as_completed(futures):
                result = future.result()
                if result['is_successful'] is True:
                    DarkLog().logger.info(result)
                    executor.shutdown(wait=False)  # 停止线程池
                    result_list.append(result)
                    results_re['is_successful'] = True
                    # return result  # 返回 True
        results_re['result'] = result_list
        return results_re
