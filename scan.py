import os
import subprocess
import time

from dark_log import DarkLog
from print_color import Colorpr
import configparser
import re
import json
import traceback

darklog = DarkLog()


class Scan:
    @staticmethod
    def get_config(value_name):
        """
        功能描述: 返回config.ini中配置文件对于值
        参数:
            value_name : 需要获取的字段名
        返回值:
        异常描述:
        调用演示:
            secret = self.get_config('secret')
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
            print(Colorpr().color_blue_bd(f"请配置{value_name}"))
            exit(0)
        return ret_data

    @staticmethod
    def identify_input(input_str):
        # 匹配 IPv4 地址（支持端口号）
        ip_regex = r'^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)(:\d{1,5})?$'
        # 匹配域名（支持端口号）
        domain_regex = r'^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}(?::\d{1,5})?$'

        if re.match(ip_regex, input_str):
            return "IP"
        elif re.match(domain_regex, input_str):
            return "Domain"
        else:
            return "Invalid"

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

    def file_name_if(self, input_file_name):  # 处理gogo结果资产
        """
        :param input_file_name: 文件地址
        :return: gogo_scan['xxx','xxx'], url_list_data['htttp://xxx','https://xxxx']
        """
        if not os.path.exists(input_file_name):
            print(Colorpr.color_blue_bd("File Not Found"))
            exit(0)
        if input_file_name is not None:
            with open(input_file_name, 'r', encoding='utf-8') as f:
                url_list = f.readlines()
            url_list_data = []  # web扫描资产
            gogo_scan = []  # gogo扫描资产
            for url in url_list:
                data = url.strip()
                if data != '':
                    # 去掉http://，https://以及/，判断是不是IP
                    # http://192.168.12.3:8080/
                    if self.identify_input(
                            data.replace("http://", '').replace("https://", '').replace("/", '')) == "IP":
                        gogo_scan.append(
                            data.replace("http://", '').replace("https://", '').replace("/", '').split(":")[0])
                    # 判断 带有https://以及http://以及正则匹配到域名
                    # https://baidu.com
                    # http://baidu.com
                    # baidu.com
                    if 'https://' in data or 'http://' in data or self.identify_input(data) == "Domain":
                        if 'http://' in data:
                            url_list_data.append(data)
                        elif 'https://' in data:
                            url_list_data.append(data)
                        else:
                            url_list_data.append("http://" + data)
                            url_list_data.append("https://" + data)
                    # 192.168.12.3:8080
                    elif self.identify_input(data) == "IP":
                        gogo_scan.append(data.split(":")[0])
                        url_list_data.append("http://" + data)
                        url_list_data.append("https://" + data)
                    else:
                        print(Colorpr.color_blue_bd(f"[ {data} ] <- No IP or Domain"))
            if len(gogo_scan) > 0 or len(url_list_data) > 0:
                return self.unique_list_(gogo_scan), self.unique_list_(url_list_data)
        else:
            return None, None

    def scan_deduplicate(self, value_case, input_batch=None, input_one=None, gogo_filename=None, observer_thread="20",
                         nuclei_args=None, proxy=None):  # 去重
        """
        功能描述: 去重，将重复的资产去掉
        参数:
            value_case : 选择哪一种方式扫描
                1. 【批量】 扫描指纹
                2. 【单个】 扫描指纹
                3. 【批量】 扫描指纹以及联动漏洞扫描
                4. 【单个】 扫描指纹以及联动漏洞扫描
                5. 【批量】 gogo 资产结果
            input_batch : 扫描目标资产信息 [数组] 去重
            input_one : 扫描目标资产信息
            gogo_filename : gogo结果文件
        文件:
            'tmp/output.json'
        返回值:
            return self.scan_observer_ward_batch(unique_arr) 【批量】 扫描指纹
            return self.scan_observer_ward_one(input_one) 【单个】 扫描指纹
            return self.scan_observer_nuclei_batch(unique_arr) 【批量】 扫描指纹以及联动漏洞扫描
            return self.scan_observer_nuclei_one(input_one) 【单个】 扫描指纹以及联动漏洞扫描
            return self.scan_gogo(gogo_filename) 批量】 gogo 资产结果 ['out.txt','['xx | xx | xx','xxx | xxx | xxx']']
        异常描述:
        调用演示:
            sc = Scan().scan_deduplicate(value_case=3, input_batch=['http://192.168.65.164:8080/', 'http://192.168.65.164:8080/',
                                                        'https://192.168.65.164:8080/'])
        """
        # unique_arr = []
        #
        # if input_batch is not None and len(input_batch) > 0:
        #     unique_arr = []
        #     seen = set()
        #     # 过滤掉空字符串
        #     filtered_batch = [item for item in input_batch if item != '']
        #     for item in filtered_batch:
        #         if item not in seen:
        #             unique_arr.append(item)
        #             seen.add(item)
        if input_batch is not None:  # 处理测绘资产
            with open('tmp/out.txt', 'w', encoding='utf-8') as out_file:
                for line in input_batch:
                    out_file.write(line + '\n')  # 每个元素后加换行符

        if value_case == 1:
            return self.scan_observer_ward_batch(input_file='tmp/out.txt', observer_thread=observer_thread,
                                                 proxy=proxy)
        elif value_case == 2 and input_one is not None:
            return self.scan_observer_ward_one(url=input_one, observer_thread=observer_thread, proxy=proxy)
        elif value_case == 3:
            return self.scan_observer_nuclei_batch(input_file='tmp/out.txt', observer_thread=observer_thread,
                                                   nuclei_args=nuclei_args, proxy=proxy)
        elif value_case == 4 and input_one is not None:
            return self.scan_observer_nuclei_one(url=input_one, observer_thread=observer_thread,
                                                 nuclei_args=nuclei_args, proxy=proxy)
        # elif value_case == 5 and gogo_filename is not None:  # gogo+指纹
        #     return self.scan_gogo(gogo_filename)

    # 功能描述: 【批量】 扫描指纹
    def scan_observer_ward_batch(self, input_file, observer_thread="20", proxy=None):
        """
        功能描述: 【批量】 扫描指纹
        参数:
            input_file : 扫描目标资产信息
            proxy : 代理
        文件:
            'tmp/output.json'
        返回值:
            {"code": 200, "data": 'tmp/output.json'} # 命令执行成功，返回200，并返回保存扫描的文件位置
            {"code": 500, "data": f"Command failed with return code {return_code}"}
            {"code": 500, "data": f"Command '{command[0]}' not found. Ensure it's installed and in your PATH."}
            {"code": 500, "data": f"An unexpected error occurred: {e}"}
        异常描述:
        调用演示:
            sc = Scan().scan_observer_ward_batch("url.txt")
        """

        # 从配置中获取其他参数
        observer_ward_exe = self.get_config("observer_ward_exe")
        observer_ward_web_fingerprint_json = self.get_config("observer_ward_web_fingerprint_json")
        with open(input_file, 'r', encoding='utf-8') as file:
            lines = file.readlines()  # 读取所有行
            cleaned_lines = [line.strip() for line in lines]  # 使用strip去掉每行的换行符
            print(Colorpr.color_red_bd(f"webscan: {cleaned_lines}"))
        # 构造命令
        command = [
            observer_ward_exe,
            "--config-dir", observer_ward_web_fingerprint_json,
            "-l", input_file,
            "-o", 'tmp/output.json',
            "--format", "json",
            "--thread", observer_thread,
        ]
        if proxy:
            if proxy.startswith('socks5://') or proxy.startswith('http://'):
                command.append("--proxy")
                command.append(proxy)
            else:
                print(Colorpr.color_blue_bd("socks5://ip:port or http://ip:port"))
                exit(0)

        # 打印调试信息以确保命令格式正确
        darklog.logger.info(f"Running command: {' '.join(command)}")
        # print("Running command:", " ".join(command))
        command_exec = "Running command: " + " ".join(command)
        print(Colorpr.color_red_bd(command_exec))

        try:
            # 使用 subprocess.Popen 以实时输出结果
            with subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=os.environ,  # 保证环境变量被继承
                    encoding='utf-8'
            ) as process:
                # 一次性获取标准输出和标准错误
                stdout, stderr = process.communicate()
                formatted_output_stderr = ""
                formatted_output_stdout = ""
                # 打印错误输出
                if stderr:
                    formatted_output_stderr = "\n\t".join(["\t|   " + line for line in stderr.strip().splitlines()])
                    # print('\t', stderr.strip())  # 打印标准输出
                    lines = stderr.split('\n')
                    new_lines = [f"\t|  {line}" for line in lines if line]  # 使用列表推导式为每行添加制表符并去除空行
                    new_stderr = '\n'.join(new_lines)
                    print(new_stderr)

                # 打印输出
                if stdout:
                    formatted_output_stdout = "\n\t".join(["\t|   " + line for line in stdout.strip().splitlines()])
                    # print('\t', stdout.strip())  # 打印标准输出
                    lines = stdout.split('\n')
                    new_lines = [f"\t|  {line}" for line in lines if line]  # 使用列表推导式为每行添加制表符并去除空行
                    new_stderr = '\n'.join(new_lines)
                    print(new_stderr)

                darklog.logger.info(
                    'stdout: ⬇' + '\n\t' + formatted_output_stderr + '\n\t' + formatted_output_stdout + '\n')  # 日志记录

                # 等待进程结束并获取退出码
                return_code = process.wait()
                if return_code == 0:
                    darklog.logger.info("Command executed successfully!")
                    print(Colorpr.color_red_bd("Command executed successfully!"))

                    return {"code": 200, "data": 'tmp/output.json'}
                else:
                    darklog.logger.warning(f"Command failed with return code {return_code}")
                    print(f"Command failed with return code {return_code}")
                    return {"code": 500, "data": f"Command failed with return code {return_code}"}

        except FileNotFoundError:
            darklog.logger.error(f"Command '{command[0]}' not found. Ensure it's installed and in your PATH.")
            print(f"Command '{command[0]}' not found. Ensure it's installed and in your PATH.")
            return {"code": 500, "data": f"Command '{command[0]}' not found. Ensure it's installed and in your PATH."}
        except Exception as e:
            darklog.logger.error(f"An unexpected error occurred: {e}")
            darklog.logger.error(f"An unexpected error occurred: {e}\n{darklog.get_error_()}")
            print(f"An unexpected error occurred: {e}")
            return {"code": 500, "data": f"An unexpected error occurred: {e}"}

    # 功能描述: 【单个】 扫描指纹
    def scan_observer_ward_one(self, url, observer_thread="20", proxy=None):
        """
        功能描述: 【单个】 扫描指纹
        参数:
            url : 需要扫描的资产
            proxy : 代理
        文件:
            'tmp/output.json'
        返回值:
            {"code": 200, "data": 'tmp/output.json'} # 命令执行成功，返回200，并返回保存扫描的文件位置
            {"code": 500, "data": f"Command failed with return code {return_code}"}
            {"code": 500, "data": f"Command '{command[0]}' not found. Ensure it's installed and in your PATH."}
            {"code": 500, "data": f"An unexpected error occurred: {e}"}
        异常描述:
        调用演示:
            sc = Scan().scan_observer_ward_one("http://192.168.65.164:8080/")
        """

        # 从配置中获取其他参数
        observer_ward_exe = self.get_config("observer_ward_exe")
        observer_ward_web_fingerprint_json = self.get_config("observer_ward_web_fingerprint_json")
        print(Colorpr.color_red_bd(f"webscan: {url}"))
        # 构造命令
        command = [
            observer_ward_exe,
            "--config-dir", observer_ward_web_fingerprint_json,
            "-t", url,
            "-o", 'tmp/output.json',
            "--format", "json",
            "--thread", observer_thread,
        ]
        if proxy:
            if proxy.startswith('socks5://') or proxy.startswith('http://'):
                command.append("--proxy")
                command.append(proxy)
            else:
                print(Colorpr.color_blue_bd("socks5://ip:port or http://ip:port"))
                exit(0)

        # 打印调试信息以确保命令格式正确
        darklog.logger.info(f"Running command: {' '.join(command)}")
        # print("Running command:", " ".join(command))
        command_exec = "Running command: " + " ".join(command)
        print(Colorpr.color_red_bd(command_exec))

        try:
            # 使用 subprocess.Popen 以实时输出结果
            with subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=os.environ,  # 保证环境变量被继承
                    encoding='utf-8'
            ) as process:
                # 一次性获取标准输出和标准错误
                stdout, stderr = process.communicate()
                formatted_output_stderr = ""
                formatted_output_stdout = ""
                # 打印错误输出
                if stderr:
                    formatted_output_stderr = "\n\t".join(["\t|   " + line for line in stderr.strip().splitlines()])
                    # print('\t', stderr.strip())  # 打印标准输出
                    lines = stderr.split('\n')
                    new_lines = [f"\t|  {line}" for line in lines if line]  # 使用列表推导式为每行添加制表符并去除空行
                    new_stderr = '\n'.join(new_lines)
                    print(new_stderr)

                # 打印输出
                if stdout:
                    formatted_output_stdout = "\n\t".join(["\t|   " + line for line in stdout.strip().splitlines()])
                    # print('\t', stdout.strip())   # 打印标准输出
                    lines = stdout.split('\n')
                    new_lines = [f"\t|  {line}" for line in lines if line]  # 使用列表推导式为每行添加制表符并去除空行
                    new_stderr = '\n'.join(new_lines)
                    print(new_stderr)

                darklog.logger.info(
                    'stdout: ⬇' + '\n\t' + formatted_output_stderr + '\n\t' + formatted_output_stdout + '\n')  # 日志记录

                # 等待进程结束并获取退出码
                return_code = process.wait()
                if return_code == 0:
                    darklog.logger.info("Command executed successfully!")
                    print(Colorpr.color_red_bd("Command executed successfully!"))
                    return {"code": 200, "data": 'tmp/output.json'}
                else:
                    darklog.logger.warning(f"Command failed with return code {return_code}")
                    print(f"Command failed with return code {return_code}")
                    return {"code": 500, "data": f"Command failed with return code {return_code}"}

        except FileNotFoundError:
            darklog.logger.error(f"Command '{command[0]}' not found. Ensure it's installed and in your PATH.")
            print(f"Command '{command[0]}' not found. Ensure it's installed and in your PATH.")
            return {"code": 500, "data": f"Command '{command[0]}' not found. Ensure it's installed and in your PATH."}
        except Exception as e:
            darklog.logger.error(f"An unexpected error occurred: {e}")
            darklog.logger.error(f"An unexpected error occurred: {e}\n{darklog.get_error_()}")
            print(f"An unexpected error occurred: {e}")
            return {"code": 500, "data": f"An unexpected error occurred: {e}"}

    # 功能描述: 【批量】 扫描指纹以及联动漏洞扫描
    def scan_observer_nuclei_batch(self, input_file, observer_thread="20", nuclei_args=None, proxy=None):
        """
        功能描述: 【批量】 扫描指纹以及联动漏洞扫描
        参数:
            input_file : 扫描目标资产信息
            proxy : 代理
            nuclei_args ： nuclei参数
        文件:
            'tmp/output.json'
        返回值:
            {"code": 200, "data": 'tmp/output.json'} # 命令执行成功，返回200，并返回保存扫描的文件位置
            {"code": 500, "data": f"Command failed with return code {return_code}"}
            {"code": 500, "data": f"Command '{command[0]}' not found. Ensure it's installed and in your PATH."}
            {"code": 500, "data": f"An unexpected error occurred: {e}"}
        异常描述:
        调用演示:
            sc = Scan().scan_observer_nuclei_batch("url.txt")
        """

        # 从配置中获取其他参数
        observer_ward_exe = self.get_config("observer_ward_exe")
        observer_ward_web_fingerprint_json = self.get_config("observer_ward_web_fingerprint_json")
        nuclei_templates = self.get_config("nuclei_templates")
        with open(input_file, 'r', encoding='utf-8') as file:
            lines = file.readlines()  # 读取所有行
            cleaned_lines = [line.strip() for line in lines]  # 使用strip去掉每行的换行符
            print(Colorpr.color_red_bd(f"webscan: {cleaned_lines}"))
        # 构造命令
        command = [
            observer_ward_exe,
            "--config-dir", observer_ward_web_fingerprint_json,
            "-l", input_file,
            "--plugin", nuclei_templates,
            "-o", 'tmp/output.json',
            "--format", "json",
            "--thread", observer_thread,
        ]
        if proxy:
            if proxy.startswith('socks5://') or proxy.startswith('http://'):
                command.append("--proxy")
                command.append(proxy)
            else:
                print(Colorpr.color_blue_bd("socks5://ip:port or http://ip:port"))
                exit(0)
        if nuclei_args:
            command.append("--nuclei-args")
            command.append(nuclei_args)

        # 打印调试信息以确保命令格式正确
        darklog.logger.info(f"Running command: {' '.join(command)}")
        # print("Running command:", " ".join(command))
        command_exec = "Running command: " + " ".join(command)
        print(Colorpr.color_red_bd(command_exec))

        try:
            # 使用 subprocess.Popen 以实时输出结果
            with subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=os.environ,  # 保证环境变量被继承
                    encoding='utf-8'
            ) as process:
                # 一次性获取标准输出和标准错误
                stdout, stderr = process.communicate()
                formatted_output_stderr = ""
                formatted_output_stdout = ""
                # 打印错误输出
                if stderr:
                    formatted_output_stderr = "\n\t".join(["\t|   " + line for line in stderr.strip().splitlines()])
                    # print('\t', stderr.strip())  # 打印标准输出
                    lines = stderr.split('\n')
                    new_lines = [f"\t|  {line}" for line in lines if line]  # 使用列表推导式为每行添加制表符并去除空行
                    new_stderr = '\n'.join(new_lines)
                    print(new_stderr)

                # 打印输出
                if stdout:
                    formatted_output_stdout = "\n\t".join(["\t|   " + line for line in stdout.strip().splitlines()])
                    # print('\t', stdout.strip())  # 打印标准输出
                    lines = stdout.split('\n')
                    new_lines = [f"\t|  {line}" for line in lines if line]  # 使用列表推导式为每行添加制表符并去除空行
                    new_stderr = '\n'.join(new_lines)
                    print(new_stderr)

                darklog.logger.info(
                    'stdout: ⬇' + '\n\t' + formatted_output_stderr + '\n\t' + formatted_output_stdout + '\n')  # 日志记录

                # 等待进程结束并获取退出码
                return_code = process.wait()
                if return_code == 0:
                    darklog.logger.info("Command executed successfully!")
                    print(Colorpr.color_red_bd("Command executed successfully!"))
                    return {"code": 200, "data": 'tmp/output.json'}
                else:
                    darklog.logger.warning(f"Command failed with return code {return_code}")
                    print(f"Command failed with return code {return_code}")
                    return {"code": 500, "data": f"Command failed with return code {return_code}"}

        except FileNotFoundError:
            darklog.logger.error(f"Command '{command[0]}' not found. Ensure it's installed and in your PATH.")
            print(f"Command '{command[0]}' not found. Ensure it's installed and in your PATH.")
            return {"code": 500, "data": f"Command '{command[0]}' not found. Ensure it's installed and in your PATH."}
        except Exception as e:
            darklog.logger.error(f"An unexpected error occurred: {e}")
            darklog.logger.error(f"An unexpected error occurred: {e}\n{darklog.get_error_()}")
            print(f"An unexpected error occurred: {e}")
            return {"code": 500, "data": f"An unexpected error occurred: {e}"}

    # 功能描述: 【单个】 扫描指纹以及联动漏洞扫描
    def scan_observer_nuclei_one(self, url, observer_thread="20", nuclei_args=None, proxy=None):
        """
        功能描述: 【单个】 扫描指纹以及联动漏洞扫描
        参数:
            url : 需要扫描的资产
            proxy : 代理
            nuclei_args ： nuclei参数
        文件:
            'tmp/output.json'
        返回值:
            {"code": 200, "data": 'tmp/output.json'} # 命令执行成功，返回200，并返回保存扫描的文件位置
            {"code": 500, "data": f"Command failed with return code {return_code}"}
            {"code": 500, "data": f"Command '{command[0]}' not found. Ensure it's installed and in your PATH."}
            {"code": 500, "data": f"An unexpected error occurred: {e}"}
        异常描述:
        调用演示:
            sc = Scan().scan_observer_nuclei_one("http://192.168.65.164:8080/")
        """

        # 从配置中获取其他参数
        observer_ward_exe = self.get_config("observer_ward_exe")
        observer_ward_web_fingerprint_json = self.get_config("observer_ward_web_fingerprint_json")
        nuclei_templates = self.get_config("nuclei_templates")
        # 构造命令
        print(Colorpr.color_red_bd(f"webscan: {url}"))
        command = [
            observer_ward_exe,
            "--config-dir", observer_ward_web_fingerprint_json,
            "-t", url,
            "-o", 'tmp/output.json',
            "--plugin", nuclei_templates,
            "--format", "json",
            "--thread", observer_thread,
        ]
        if proxy:
            if proxy.startswith('socks5://') or proxy.startswith('http://'):
                command.append("--proxy")
                command.append(proxy)
            else:
                print(Colorpr.color_blue_bd("socks5://ip:port or http://ip:port"))
                exit(0)
        if nuclei_args:
            command.append("--nuclei-args")
            command.append(nuclei_args)

        # 打印调试信息以确保命令格式正确
        darklog.logger.info(f"Running command: {' '.join(command)}")
        # print("Running command:", " ".join(command))
        command_exec = "Running command: " + " ".join(command)
        print(Colorpr.color_red_bd(command_exec))

        try:
            # 使用 subprocess.Popen 以实时输出结果
            with subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=os.environ,  # 保证环境变量被继承
                    encoding='utf-8'
            ) as process:
                # 一次性获取标准输出和标准错误
                stdout, stderr = process.communicate()
                formatted_output_stderr = ""
                formatted_output_stdout = ""
                # 打印错误输出
                if stderr:
                    formatted_output_stderr = "\n\t".join(["\t|   " + line for line in stderr.strip().splitlines()])
                    # print('\t', stderr.strip())  # 打印标准输出
                    lines = stderr.split('\n')
                    new_lines = [f"\t|  {line}" for line in lines if line]  # 使用列表推导式为每行添加制表符并去除空行
                    new_stderr = '\n'.join(new_lines)
                    print(new_stderr)

                # 打印输出
                if stdout:
                    formatted_output_stdout = "\n\t".join(["\t|   " + line for line in stdout.strip().splitlines()])
                    # print('\t', stdout.strip())  # 打印标准输出
                    lines = stdout.split('\n')
                    new_lines = [f"\t|  {line}" for line in lines if line]  # 使用列表推导式为每行添加制表符并去除空行
                    new_stderr = '\n'.join(new_lines)
                    print(new_stderr)

                darklog.logger.info(
                    'stdout: ⬇' + '\n\t' + formatted_output_stderr + '\n\t' + formatted_output_stdout + '\n')  # 日志记录

                # 等待进程结束并获取退出码
                return_code = process.wait()
                if return_code == 0:
                    darklog.logger.info("Command executed successfully!")
                    print(Colorpr.color_red_bd("Command executed successfully!"))
                    return {"code": 200, "data": 'tmp/output.json'}
                else:
                    darklog.logger.warning(f"Command failed with return code {return_code}")
                    print(f"Command failed with return code {return_code}")
                    return {"code": 500, "data": f"Command failed with return code {return_code}"}

        except FileNotFoundError:
            darklog.logger.error(f"Command '{command[0]}' not found. Ensure it's installed and in your PATH.")
            print(f"Command '{command[0]}' not found. Ensure it's installed and in your PATH.")
            return {"code": 500, "data": f"Command '{command[0]}' not found. Ensure it's installed and in your PATH."}
        except Exception as e:
            darklog.logger.error(f"An unexpected error occurred: {e}")
            darklog.logger.error(f"An unexpected error occurred: {e}\n{darklog.get_error_()}")
            print(f"An unexpected error occurred: {e}")
            return {"code": 500, "data": f"An unexpected error occurred: {e}"}

    def scan_gogo(self, input_file, gogo_port='80,443,8080', thread="1000", gogo_poc=None, proxy=None):
        """
        功能描述: 【批量】 gogo扫描
        参数:
            input_file: 扫描的文件 [.txt]
            port : 需要扫描的资产端口
            thread: 线程
            gogo_poc: 是否开启ev  [true ot False]
            gogo_proxy : 代理
        文件:
        返回值:
            {"code": 200, "data": ['tmp/out.txt', json_filename_gogo]}
            json_filename_gogo['ip | port | xxx | xxx | xx']
        异常描述:
        调用演示:
            sc = Scan().scan_observer_nuclei_one("http://192.168.65.164:8080/")
        """
        gogo_scan, url_list_data = self.file_name_if(input_file)
        if gogo_scan is not None:
            with open('tmp/gogo_out.txt', 'w', encoding='utf-8') as out_file:
                for line in gogo_scan:
                    out_file.write(line + '\n')  # 每个元素后加换行符
        print(Colorpr.color_red_bd(f"gogo_scan: {gogo_scan}"))

        # 从配置中获取其他参数
        gogo_exe = self.get_config("gogo_exe")

        if os.path.exists('tmp/gogo_out.txt'):
            os.remove('tmp/gogo_out.txt')
        if os.path.exists("tmp/gogo_output.json"):
            os.remove("tmp/gogo_output.json")

        # 构造命令
        command = [
            gogo_exe,
            "-l", input_file,
            "-f", 'tmp/gogo_out.txt',
            "-p", gogo_port,
            "-t", thread,
        ]

        if gogo_poc:
            command.append("-ev")
            # 构造命令
        if proxy:
            if proxy.startswith('socks5://') or proxy.startswith('http://'):
                command.append("--proxy")
                command.append(proxy)
            else:
                print(Colorpr.color_blue_bd("socks5://ip:port or http://ip:port"))
                exit(0)

        # 打印调试信息以确保命令格式正确
        darklog.logger.info(f"Running command: {' '.join(command)}")
        # print("Running command:", " ".join(command))
        command_exec = "Running command: " + " ".join(command)
        print(Colorpr.color_red_bd(command_exec))

        try:
            # 使用 subprocess.Popen 以实时输出结果
            with subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=os.environ,  # 保证环境变量被继承
                    encoding='utf-8'
            ) as process:
                # 一次性获取标准输出和标准错误
                stdout, stderr = process.communicate()
                formatted_output_stderr = ""
                formatted_output_stdout = ""
                # 打印错误输出
                if stderr:
                    formatted_output_stderr = "\n\t".join(["\t|   " + line for line in stderr.strip().splitlines()])
                    # print('\t', stderr.strip())  # 打印标准输出
                    darklog.logger.info('stderr error: ⬇' + '\n\t' + formatted_output_stderr + '\n')  # 日志记录

                # 打印输出
                if stdout:
                    formatted_output_stdout = "\n\t".join(["\t|   " + line for line in stdout.strip().splitlines()])
                    # print('\t', stdout.strip())  # 打印标准输出
                    lines = stdout.split('\n')
                    new_lines = [f"\t|  {line}" for line in lines if line]  # 使用列表推导式为每行添加制表符并去除空行
                    new_stderr = '\n'.join(new_lines)
                    print(new_stderr)

                darklog.logger.info(
                    'stdout: ⬇' + '\n\t' + formatted_output_stdout + '\n')  # 日志记录

                # 等待进程结束并获取退出码
                return_code = process.wait()
                time.sleep(2)  # 延迟等待.sock.lock文件解锁
                if return_code == 0 and os.path.exists('tmp/gogo_out.txt'):
                    command_json = [
                        gogo_exe,
                        "-F", 'tmp/gogo_out.txt',
                        "-o", "json",
                        "-f", "tmp/gogo_output.json",
                    ]
                    # 打印调试信息以确保命令格式正确
                    darklog.logger.info(f"Running command: {' '.join(command_json)}")
                    # print("Running command:", " ".join(command))
                    command_exec = "Running command: " + " ".join(command_json)
                    print(Colorpr.color_red_bd(command_exec))

                    with subprocess.Popen(
                            command_json,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            env=os.environ,  # 保证环境变量被继承
                            encoding='utf-8'
                    ) as process_json:
                        # 一次性获取标准输出和标准错误
                        stdout, stderr = process_json.communicate()

                        # 打印错误输出
                        if stderr:
                            formatted_output_stderr = "\n\t".join(
                                ["\t|   " + line for line in stderr.strip().splitlines()])
                            # print('\t', stderr.strip())  # 打印标准输出
                            darklog.logger.info('stderr error: ⬇' + '\n\t' + formatted_output_stderr + '\n')  # 日志记录

                        # 打印输出
                        if stdout:
                            formatted_output_stdout = "\n\t".join(
                                ["\t|   " + line for line in stdout.strip().splitlines()])
                            # print('\t', stdout.strip())  # 打印标准输出
                            lines = stdout.split('\n')
                            new_lines = [f"\t|  {line}" for line in lines if line]  # 使用列表推导式为每行添加制表符并去除空行
                            new_stderr = '\n'.join(new_lines)
                            print(new_stderr)

                        darklog.logger.info(
                            'stdout: ⬇' + '\n\t' + formatted_output_stdout + '\n')  # 日志记录

                        # 等待进程结束并获取退出码
                        return_code = process_json.wait()
                        if return_code == 0 and os.path.exists("tmp/gogo_output.json"):
                            darklog.logger.info("Command executed successfully!")
                            print(Colorpr.color_red_bd("Command executed successfully!"))
                            json_filename_ = []  # 待扫描web站点
                            json_filename_gogo = []  # web站点
                            with open('tmp/gogo_output.json', 'r', encoding='utf-8') as f:
                                json_data = json.load(f)
                                for line in json_data['data']:
                                    if line['protocol'] == 'http' or line['protocol'] == 'https':  # web站点
                                        frameworks = line.get('frameworks', '')
                                        host = line.get('host', '')
                                        try:
                                            if len(host) > 0:
                                                for i_host in host:
                                                    json_filename_.append(
                                                        line['protocol'] + '://' + i_host + ':' + line['port'])
                                            json_filename_.append(
                                                line['protocol'] + '://' + line['ip'] + ':' + line['port'])
                                            json_filename_gogo.append({
                                                "ip": line['ip'],
                                                "port": line['port'],
                                                "protocol": line['protocol'],
                                                "status": line['status'],
                                                "title": line['title'],
                                                "host": host,
                                                "frameworks": str(frameworks)
                                            })
                                        except KeyError:
                                            darklog.logger.error(f"KeyError: {darklog.get_error_()}")
                                    else:  # tcp站点
                                        try:
                                            frameworks = line.get('frameworks', '')
                                            host = line.get('host', '')
                                            json_filename_gogo.append({
                                                "ip": line['ip'],
                                                "port": line['port'],
                                                "protocol": line['protocol'],
                                                "status": line['status'],
                                                "title": line['title'],
                                                "host": host,
                                                "frameworks": str(frameworks)
                                            })
                                        except KeyError:
                                            darklog.logger.error(f"KeyError: {darklog.get_error_()}")
                            url_list_data.extend(json_filename_)
                            unique_arr = self.unique_list_(url_list_data)  # 去重
                            with open('tmp/out.txt', 'w', encoding='utf-8') as out_file:
                                for line in unique_arr:
                                    out_file.write(line + '\n')  # 每个元素后加换行符

                            return {"code": 200, "data": ['tmp/out.txt', json_filename_gogo]}
                        else:
                            darklog.logger.warning(f"Command failed with return code {return_code}")
                            print(f"Command failed with return code {return_code}")
                            return {"code": 500, "data": f"Command failed with return code {return_code}"}
                else:
                    darklog.logger.warning(f"Command failed with return code {return_code}")
                    print(Colorpr.color_blue_bd(f"Command failed with return code {return_code}"))
                    return {"code": 500, "data": f"Command failed with return code {return_code}"}
        except Exception as e:
            print(Colorpr.color_blue_bd(f"An unexpected error occurred: {e}"))
            darklog.logger.error(f"An unexpected error occurred: {e}")
            darklog.logger.error(f"An unexpected error occurred: {e}\n{darklog.get_error_()}")
            return {"code": 500, "data": f"An unexpected error occurred: {e}"}

    def scan_gogo_one(self, url, gogo_port='80,443,8080', thread="1000", gogo_poc=None, proxy=None):
        """
        功能描述: 【批量】 gogo扫描
        参数:
            url: 需要扫描的URL or ip
            port : 需要扫描的资产端口
            thread: 线程
            gogo_poc: 是否开启ev  [true ot False]
            gogo_proxy : 代理
        文件:
        返回值:
            {"code": 200, "data": ['tmp/out.txt', json_filename_gogo]}
            json_filename_gogo['ip | port | xxx | xxx | xx']
        异常描述:
        调用演示:
            sc = Scan().scan_observer_nuclei_one("http://192.168.65.164:8080/")
            sc = Scan().scan_observer_nuclei_one("192.168.65.164:")
        """
        url_list_data = []
        print(Colorpr.color_red_bd(f"gogo_scan: {url}"))

        # 从配置中获取其他参数
        gogo_exe = self.get_config("gogo_exe")

        if os.path.exists('tmp/gogo_out.txt'):
            os.remove('tmp/gogo_out.txt')
        if os.path.exists("tmp/gogo_output.json"):
            os.remove("tmp/gogo_output.json")

        # 构造命令
        command = [
            gogo_exe,
            "-i", url,
            "-f", 'tmp/gogo_out.txt',
            "-p", gogo_port,
            "-t", thread,
        ]

        if gogo_poc:
            command.append("-ev")
            # 构造命令
        if proxy:
            if proxy.startswith('socks5://') or proxy.startswith('http://'):
                command.append("--proxy")
                command.append(proxy)
            else:
                print(Colorpr.color_blue_bd("socks5://ip:port or http://ip:port"))
                exit(0)

        # 打印调试信息以确保命令格式正确
        darklog.logger.info(f"Running command: {' '.join(command)}")
        # print("Running command:", " ".join(command))
        command_exec = "Running command: " + " ".join(command)
        print(Colorpr.color_red_bd(command_exec))

        try:
            # 使用 subprocess.Popen 以实时输出结果
            with subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=os.environ,  # 保证环境变量被继承
                    encoding='utf-8'
            ) as process:
                # 一次性获取标准输出和标准错误
                stdout, stderr = process.communicate()
                formatted_output_stderr = ""
                formatted_output_stdout = ""
                # 打印错误输出
                if stderr:
                    formatted_output_stderr = "\n\t".join(["\t|   " + line for line in stderr.strip().splitlines()])
                    # print('\t', stderr.strip())  # 打印标准输出
                    darklog.logger.info('stderr error: ⬇' + '\n\t' + formatted_output_stderr + '\n')  # 日志记录

                # 打印输出
                if stdout:
                    formatted_output_stdout = "\n\t".join(["\t|   " + line for line in stdout.strip().splitlines()])
                    # print('\t', stdout.strip())  # 打印标准输出
                    lines = stdout.split('\n')
                    new_lines = [f"\t|  {line}" for line in lines if line]  # 使用列表推导式为每行添加制表符并去除空行
                    new_stderr = '\n'.join(new_lines)
                    print(new_stderr)

                darklog.logger.info(
                    'stdout: ⬇' + '\n\t' + formatted_output_stdout + '\n')  # 日志记录

                # 等待进程结束并获取退出码
                return_code = process.wait()
                time.sleep(2)  # 延迟等待.sock.lock文件解锁
                if return_code == 0 and os.path.exists('tmp/gogo_out.txt'):
                    command_json = [
                        gogo_exe,
                        "-F", 'tmp/gogo_out.txt',
                        "-o", "json",
                        "-f", "tmp/gogo_output.json",
                    ]
                    # 打印调试信息以确保命令格式正确
                    darklog.logger.info(f"Running command: {' '.join(command_json)}")
                    # print("Running command:", " ".join(command))
                    command_exec = "Running command: " + " ".join(command_json)
                    print(Colorpr.color_red_bd(command_exec))

                    with subprocess.Popen(
                            command_json,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            env=os.environ,  # 保证环境变量被继承
                            encoding='utf-8'
                    ) as process_json:
                        # 一次性获取标准输出和标准错误
                        stdout, stderr = process_json.communicate()
                        formatted_output_stderr = ""
                        formatted_output_stdout = ""
                        # 打印错误输出
                        if stderr:
                            formatted_output_stderr = "\n\t".join(
                                ["\t|   " + line for line in stderr.strip().splitlines()])
                            # print('\t', stderr.strip())  # 打印标准输出
                            darklog.logger.info('stderr error: ⬇' + '\n\t' + formatted_output_stderr + '\n')  # 日志记录

                        # 打印输出
                        if stdout:
                            formatted_output_stdout = "\n\t".join(
                                ["\t|   " + line for line in stdout.strip().splitlines()])
                            # print('\t', stdout.strip())  # 打印标准输出
                            lines = stdout.split('\n')
                            new_lines = [f"\t|  {line}" for line in lines if line]  # 使用列表推导式为每行添加制表符并去除空行
                            new_stderr = '\n'.join(new_lines)
                            print(new_stderr)

                        darklog.logger.info(
                            'stdout: ⬇' + '\n\t' + formatted_output_stdout + '\n')  # 日志记录

                        # 等待进程结束并获取退出码
                        return_code = process_json.wait()
                        if return_code == 0 and os.path.exists("tmp/gogo_output.json"):
                            darklog.logger.info("Command executed successfully!")
                            print(Colorpr.color_red_bd("Command executed successfully!"))
                            json_filename_ = []  # 待扫描web站点
                            json_filename_gogo = []  # web站点
                            with open('tmp/gogo_output.json', 'r', encoding='utf-8') as f:
                                json_data = json.load(f)
                                for line in json_data['data']:
                                    if line['protocol'] == 'http' or line['protocol'] == 'https':  # web站点
                                        frameworks = line.get('frameworks', '')
                                        host = line.get('host', '')
                                        try:
                                            if len(host) > 0:
                                                for i_host in host:
                                                    json_filename_.append(
                                                        line['protocol'] + '://' + i_host + ':' + line['port'])
                                            json_filename_.append(
                                                line['protocol'] + '://' + line['ip'] + ':' + line['port'])
                                            json_filename_gogo.append({
                                                "ip": line['ip'],
                                                "port": line['port'],
                                                "protocol": line['protocol'],
                                                "status": line['status'],
                                                "title": line['title'],
                                                "host": host,
                                                "frameworks": str(frameworks)
                                            })
                                        except KeyError:
                                            darklog.logger.error(f"KeyError: {darklog.get_error_()}")
                                    else:  # tcp站点
                                        try:
                                            frameworks = line.get('frameworks', '')
                                            host = line.get('host', '')
                                            title = line.get('title', '')
                                            json_filename_gogo.append({
                                                "ip": line['ip'],
                                                "port": line['port'],
                                                "protocol": line['protocol'],
                                                "status": line['status'],
                                                "title": title,
                                                "host": host,
                                                "frameworks": str(frameworks)
                                            })
                                        except KeyError:
                                            darklog.logger.error(f"KeyError: {darklog.get_error_()}")
                            url_list_data.extend(json_filename_)
                            unique_arr = self.unique_list_(url_list_data)  # 去重
                            with open('tmp/out.txt', 'w', encoding='utf-8') as out_file:
                                for line in unique_arr:
                                    out_file.write(line + '\n')  # 每个元素后加换行符

                            return {"code": 200, "data": ['tmp/out.txt', json_filename_gogo]}
                        else:
                            darklog.logger.warning(f"Command failed with return code {return_code}")
                            print(f"Command failed with return code {return_code}")
                            return {"code": 500, "data": f"Command failed with return code {return_code}"}
                else:
                    darklog.logger.warning(f"Command failed with return code {return_code}")
                    print(Colorpr.color_blue_bd(f"Command failed with return code {return_code}"))
                    return {"code": 500, "data": f"Command failed with return code {return_code}"}
        except Exception as e:
            print(Colorpr.color_blue_bd(f"An unexpected error occurred: {e}"))
            darklog.logger.error(f"An unexpected error occurred: {e}")
            darklog.logger.error(f"An unexpected error occurred: {e}\n{darklog.get_error_()}")
            return {"code": 500, "data": f"An unexpected error occurred: {e}"}
