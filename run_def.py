import json

from scan import Scan
from dark_log import DarkLog
from cyberspace_search import Cyberspace
from savefile import SaveFile
from resultdata import ResultData
import argparse
from print_color import Colorpr
import re
from parse_c2 import C2run, list_all_files, read_yaml
import os

darklog = DarkLog()


def check_url_ip(value):
    """
    功能描述: 正则匹配URL或IP地址。

    参数:
        value (str 或 list): 需要检查的字符串（可能是URL或IP），或者是一个包含多个URL或IP的列表。

    返回值:
        如果传入的是单个字符串：
            - 匹配成功返回 True，否则退出程序并打印错误信息。
        如果传入的是列表：
            - 返回一个包含所有匹配成功的结果的列表，匹配失败的元素会打印错误信息并跳过。
    """
    if value is None:
        return value
    url_ip_domain_pattern = re.compile(
        r'^(https?://)?'  # 匹配 http:// 或 https://，可选
        r'('
        r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'  # 匹配域名（如 example.com）
        r'|'  # 或
        r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'  # 匹配 IP 地址
        r')'
        r'(:\d+)?'  # 匹配端口号（如 :8080），可选
        r'(/.*)?'  # 匹配路径和查询参数（如 /path?query=1），可选
        r'$'  # 确保匹配到字符串末尾
    )

    # 如果是列表
    if isinstance(value, list):
        result = []
        for item in value:
            if url_ip_domain_pattern.match(item):
                result.append(item)  # 匹配成功，添加到结果列表
            else:
                print(Colorpr.color_blue_bd(f"Invalid input type: {item}"))  # 匹配失败，打印错误信息
        return result  # 返回匹配成功的结果列表

    # 如果是单个字符串
    elif isinstance(value, str):
        if url_ip_domain_pattern.match(value):
            return value
        else:
            print(Colorpr.color_blue_bd(f"Invalid input type: {value}"))
            exit(0)

    # 如果传入的不是字符串或列表
    else:
        print(Colorpr.color_blue_bd("Invalid input type. Expected str or list."))
        exit(0)


def check_file(value):
    """
    功能描述: 判断文件是否存在

    参数:
        value (str): 需要检查的字符串（可能是URL或IP）。

    返回值:
        bool: 如果匹配成功返回True，否则返回None。
    """
    if value is None:
        return value
    if os.path.exists(value):
        return value
    print(Colorpr.color_blue_bd(f"File Not Found: {value}"))
    exit(0)


def NSM_subcommand(args):
    """
    功能描述: 处理NSM子命令，根据输入参数进行网络空间测绘和扫描。

    参数:
        args (argparse.Namespace): 命令行参数对象。

    逻辑:
        - 根据提供的参数（domain, icp, ip, body, title）获取网络空间数据。
        - 根据用户选择的扫描模式（observer, nuclei）执行相应的扫描任务。
        - 保存结果并生成HTML报告。
    """
    # 确定文件名并打印输入参数
    filename = None
    if args.domain:
        filename = args.domain
        print(Colorpr.color_red_bd(args.domain))
    elif args.icp:
        filename = args.icp
        print(Colorpr.color_red_bd(args.icp))
    elif args.ip:
        filename = args.ip
        print(Colorpr.color_red_bd(args.ip))
    elif args.body:
        filename = args.body
        print(Colorpr.color_red_bd(args.body))
    elif args.title:
        filename = args.title
        print(Colorpr.color_red_bd(args.title))
    else:
        print(Colorpr.color_blue_bd("至少输入一个参数"))
        print(Colorpr.color_blue_bd("main.py NSM -h"))
        exit(0)

    # 获取网络空间数据
    fofa_json_data = Cyberspace().get_cyberspace(ip=args.ip, domain=args.domain, icp=args.icp, body=args.body,
                                                 title=args.title, size=args.quake_size, proxy=args.proxy)
    if fofa_json_data['code'] != 200:
        print(Colorpr.color_blue_bd(fofa_json_data))
        darklog.logger.error(fofa_json_data)
        exit(0)

    if args.observer:
        darklog.logger.info("测绘+指纹")
        print(Colorpr.color_red_bd("测绘+指纹"))
        sc_json = Scan().scan_deduplicate(value_case=1, input_batch=fofa_json_data['data'],
                                          observer_thread=args.observer_thread, proxy=args.proxy)
        observer_ward_json_result, nuclei_json_result = ResultData().scan_result(sc_json)
        SaveFile().file_cyberspace_txt(filename, fofa_json_data)
        SaveFile().file_observer_ward_txt(filename, observer_ward_json_result)
        SaveFile().file_nuclei_txt(filename, nuclei_json_result)
        SaveFile().generate_html_report(filename=filename, cyberspace_search_html=fofa_json_data['data'],
                                        gogo_scan_html=[],
                                        observer_ward_html=observer_ward_json_result['data'],
                                        nuclei_scan_html=nuclei_json_result['data'])
    elif args.nuclei:
        darklog.logger.info("测绘+指纹+漏洞")
        print(Colorpr.color_red_bd("测绘+指纹+漏洞"))
        sc_json = Scan().scan_deduplicate(value_case=3, input_batch=fofa_json_data['data'],
                                          observer_thread=args.observer_thread, nuclei_args=args.nuclei_args,
                                          proxy=args.proxy)
        observer_ward_json_result, nuclei_json_result = ResultData().scan_result(sc_json)
        SaveFile().file_cyberspace_txt(filename, fofa_json_data)
        SaveFile().file_observer_ward_txt(filename, observer_ward_json_result)
        SaveFile().file_nuclei_txt(filename, nuclei_json_result)
        SaveFile().generate_html_report(filename=filename, cyberspace_search_html=fofa_json_data['data'],
                                        gogo_scan_html=[],
                                        observer_ward_html=observer_ward_json_result['data'],
                                        nuclei_scan_html=nuclei_json_result['data'])
    else:
        darklog.logger.info("导出测绘资产")
        print(Colorpr.color_red_bd("导出测绘资产"))
        SaveFile().file_cyberspace_txt(filename, fofa_json_data)
        SaveFile().generate_html_report(filename=filename, cyberspace_search_html=fofa_json_data['data'],
                                        gogo_scan_html=[],
                                        observer_ward_html=[],
                                        nuclei_scan_html=[])


def WEBSCAN_subcommand(args):
    """
    功能描述: 处理WEBSCAN子命令，根据输入参数进行单个或批量目标的指纹和漏洞扫描。

    参数:
        args (argparse.Namespace): 命令行参数对象。

    逻辑:
        - 根据提供的参数（observer, nuclei, observer_file, nuclei_file）选择扫描模式。
        - 执行相应的扫描任务并保存结果，生成HTML报告。
    """
    if not (args.observer or args.nuclei or args.observer_file or args.nuclei_file):
        print(Colorpr.color_blue_bd("WEBSCAN -h"))
    elif args.observer:
        check_url_ip(args.observer)
        darklog.logger.info("单个目标指纹扫描")
        print(Colorpr.color_red_bd("单个目标指纹扫描"))
        sc_json = Scan().scan_deduplicate(value_case=2, input_one=args.observer,
                                          observer_thread=args.observer_thread, proxy=args.proxy)
        observer_ward_json_result, nuclei_json_result = ResultData().scan_result(sc_json)
        SaveFile().file_observer_ward_txt(args.observer, observer_ward_json_result)
        SaveFile().file_nuclei_txt(args.observer, nuclei_json_result)
        SaveFile().generate_html_report(filename=args.observer_thread, cyberspace_search_html=[],
                                        gogo_scan_html=[],
                                        observer_ward_html=observer_ward_json_result['data'],
                                        nuclei_scan_html=nuclei_json_result['data'])
    elif args.nuclei:
        check_url_ip(args.nuclei)
        darklog.logger.info("单个目标指纹漏洞扫描")
        print(Colorpr.color_red_bd("单个目标指纹漏洞扫描"))
        sc_json = Scan().scan_deduplicate(value_case=4, input_one=args.nuclei, observer_thread=args.observer_thread,
                                          nuclei_args=args.nuclei_args, proxy=args.proxy)
        observer_ward_json_result, nuclei_json_result = ResultData().scan_result(sc_json)
        SaveFile().file_observer_ward_txt(args.nuclei, observer_ward_json_result)
        SaveFile().file_nuclei_txt(args.nuclei, nuclei_json_result)
        SaveFile().generate_html_report(filename=args.nuclei, cyberspace_search_html=[],
                                        gogo_scan_html=[],
                                        observer_ward_html=observer_ward_json_result['data'],
                                        nuclei_scan_html=nuclei_json_result['data'])
    elif args.observer_file:
        check_file(args.observer_file)
        darklog.logger.info("批量目标指纹扫描")
        print(Colorpr.color_red_bd("批量目标指纹扫描"))
        data_list = [line.strip() for line in open(args.observer_file, 'r', encoding='utf-8').readlines()]
        data_list = check_url_ip(Scan().unique_list_(data_list))

        sc_json = Scan().scan_deduplicate(value_case=1, input_batch=data_list,
                                          observer_thread=args.observer_thread, proxy=args.proxy)
        observer_ward_json_result, nuclei_json_result = ResultData().scan_result(sc_json)
        file_time = SaveFile.formatted_time()
        SaveFile().file_observer_ward_txt(file_time, observer_ward_json_result)
        SaveFile().file_nuclei_txt(file_time, nuclei_json_result)
        SaveFile().generate_html_report(filename=file_time, cyberspace_search_html=[],
                                        gogo_scan_html=[],
                                        observer_ward_html=observer_ward_json_result['data'],
                                        nuclei_scan_html=nuclei_json_result['data'])
    elif args.nuclei_file:
        check_file(args.observer_file)
        darklog.logger.info("批量目标指纹漏洞扫描")
        print(Colorpr.color_red_bd("批量目标指纹漏洞扫描"))
        data_list = [line.strip() for line in open(args.nuclei_file, 'r', encoding='utf-8').readlines()]
        data_list = check_url_ip(Scan().unique_list_(data_list))

        sc_json = Scan().scan_deduplicate(value_case=3, input_batch=data_list,
                                          observer_thread=args.observer_thread, nuclei_args=args.nuclei_args,
                                          proxy=args.proxy)
        observer_ward_json_result, nuclei_json_result = ResultData().scan_result(sc_json)
        file_time = SaveFile.formatted_time()
        SaveFile().file_observer_ward_txt(file_time, observer_ward_json_result)
        SaveFile().file_nuclei_txt(file_time, nuclei_json_result)
        SaveFile().generate_html_report(filename=file_time, cyberspace_search_html=[],
                                        gogo_scan_html=[],
                                        observer_ward_html=observer_ward_json_result['data'],
                                        nuclei_scan_html=nuclei_json_result['data'])
    else:
        print(Colorpr.color_blue_bd("-b or -n or -bl or nl is null"))


def GOGO_command(args):
    """
    功能描述: 处理GOGO子命令，根据输入参数进行目标扫描，并结合指纹和漏洞扫描。

    参数:
        args (argparse.Namespace): 命令行参数对象。

    逻辑:
        - 根据提供的参数（observer, nuclei, file, ip）选择扫描模式。
        - 执行相应的扫描任务并保存结果，生成HTML报告。
    """
    if not ((args.observer or args.nuclei) and (args.file or args.ip)):
        print(Colorpr.color_blue_bd("GOGO -h"))
        print(Colorpr.color_blue_bd("-b or -n is null"))
        print(Colorpr.color_blue_bd("-f or -i is null"))
    else:
        if args.observer:
            darklog.logger.info("gogo+指纹")
            print(Colorpr.color_red_bd("gogo+指纹"))
        elif args.nuclei:
            darklog.logger.info("gogo+指纹+漏洞")
            print(Colorpr.color_red_bd("gogo+指纹+漏洞"))

        if args.file:
            check_file(args.file)
            code_data = Scan().scan_gogo(input_file=args.file, gogo_port=args.gogo_port, thread=args.gogo_thread,
                                         gogo_poc=args.gogo_poc, proxy=args.proxy)
            file_name = SaveFile.formatted_time()
        elif args.ip:
            check_url_ip(args.ip)
            code_data = Scan().scan_gogo_one(url=args.ip, gogo_port=args.gogo_port, thread=args.gogo_thread,
                                             gogo_poc=args.gogo_poc, proxy=args.proxy)
            file_name = args.ip

        if code_data['code'] != 200:
            print(Colorpr.color_blue_bd('No port'))
            return code_data

        print(Colorpr.color_red_bd("gogo data ⬇"))
        for i in code_data['data'][1]:
            for key, value in i.items():
                if value != "":
                    print(str(key) + ": " + str(value))
            print()

        if args.observer:
            sc_json = Scan().scan_observer_ward_batch(code_data['data'][0], observer_thread=args.observer_thread,
                                                      proxy=args.proxy)
        elif args.nuclei:
            sc_json = Scan().scan_observer_nuclei_batch(code_data['data'][0], observer_thread=args.observer_thread,
                                                        nuclei_args=args.nuclei_args, proxy=args.proxy)
        observer_ward_json_result, nuclei_json_result = ResultData().scan_result(sc_json)

        SaveFile().file_gogo_txt(file_name, code_data['data'][1])
        SaveFile().file_observer_ward_txt(file_name, observer_ward_json_result)
        SaveFile().file_nuclei_txt(file_name, nuclei_json_result)
        SaveFile().generate_html_report(filename=file_name, cyberspace_search_html=[],
                                        gogo_scan_html=code_data['data'][1],
                                        observer_ward_html=observer_ward_json_result['data'],
                                        nuclei_scan_html=nuclei_json_result['data'])


def RTScan_command(args):
    if args.all_yaml:
        print(Colorpr.color_red_bd('Red Team Infrastructure Scan Template'))
        file_names = list_all_files()
        print('|type', end="   ")
        print("\t | name | tags")
        print('---------------------------------------------')
        for file_name in file_names:
            yaml_data = read_yaml(file_name)
            file_tags = yaml_data.get('id', '').split(',')
            file_classification = yaml_data.get('info', '').get('classification', '').split(',')
            tags = yaml_data.get('info', '').get('tags', '').split(',')
            if file_classification[0] == 'C2':
                print("|" + file_classification[0], end="      ")
            elif file_classification[0] == 'tools':
                print("|" + file_classification[0], end="      ")
            else:
                print("|" + file_classification[0], end="")
            print("\t | " + file_tags[0], end="")
            print(' | '+Colorpr.color_red(','.join(tags)))
        exit(0)
    """
    功能描述: 处理RTScan子命令，根据输入参数进行红队基础设施扫描。

    参数:
        args (argparse.Namespace): 命令行参数对象。

    逻辑:
        - 根据提供的参数（file, ip）选择扫描模式。
        - 执行C2扫描并保存结果，生成HTML报告。
    """
    if not (args.file or args.ip):
        print(Colorpr.color_blue_bd("RTScan -h"))
        print(Colorpr.color_blue_bd("-f or -i is null"))
    else:
        darklog.logger.info("扫描红队基础设施")
        print(Colorpr.color_red_bd("扫描红队基础设施"))
        if args.tags:
            print(Colorpr.color_red_bd("tags: "+args.tags))

        if args.file:
            check_file(args.file)
            code_data = Scan().scan_gogo(input_file=args.file, gogo_port=args.gogo_port, thread=args.gogo_thread,
                                         gogo_poc=args.gogo_poc, proxy=args.proxy)
            file_names = SaveFile.formatted_time()
        elif args.ip:
            check_url_ip(args.ip)
            code_data = Scan().scan_gogo_one(url=args.ip, gogo_port=args.gogo_port, thread=args.gogo_thread,
                                             gogo_poc=args.gogo_poc, proxy=args.proxy)
            file_names = args.ip

        if code_data['code'] != 200:
            print(Colorpr.color_blue_bd('No port'))
            return code_data

        print(Colorpr.color_red_bd("gogo data ⬇"))
        for i in code_data['data'][1]:
            for key, value in i.items():
                if value != "":
                    print(str(key) + ": " + str(value))
            print()

        print(Colorpr.color_red_bd("RTScan data ⬇"))
        hml_c2_list = []
        for i in code_data['data'][1]:
            c2 = C2run().main(ip=i['ip'], port=i['port'], protocol=i['protocol'], proxy=args.proxy,
                              file_yaml=check_file(args.file_yaml), tags=args.tags)
            if c2['is_successful']:
                for result in c2['result']:
                    html_ = {
                        "ip": f"{i['protocol']}://{i['ip']}:{i['port']}",
                        "id": result.get("id", ""),
                        "version": result.get("version", ""),
                        "type": result.get("type", ""),
                        "name": result.get("name", ""),
                        "author": result.get("author", ""),
                        "severity": result.get("severity", ""),
                        "metadata": result.get("metadata", {}),
                        "query": result.get("query", {}),
                        "tcp_tf": result.get("tcp_tf", ""),
                        "http_tf": result.get("http_tf", ""),
                        "jarm_hash": result.get("jarm_hash", [])
                    }
                    print(Colorpr.color_red_bd(f"id:{Colorpr.color_red(result.get('id'))}"))
                    print(Colorpr.color_red_bd(f"{i['protocol']}://{i['ip']}:{i['port']}"))
                    if result["http_tf"].get('is_successful'):
                        html_['http_rule'] = "hit rule"
                        print("\t | http:" + Colorpr.color_red("hit rule"))
                    if result["tcp_tf"].get('is_successful'):
                        html_['tcp_rule'] = "hit rule"
                        print("\t | tcp:" + Colorpr.color_red("hit rule"))
                    if result["jarm_hash"]:
                        html_['jarm_tf'] = "hit rule"
                        print("\t | jarm:" + Colorpr.color_red("hit rule"))
                    print(f"\t | version:{result.get('version')}")
                    print(f"\t | type:" + Colorpr.color_red(result.get('type')))
                    print("\t | name:" + Colorpr.color_purple(result.get('name')))
                    print(f"\t | author:{result.get('author')}")
                    print(f"\t | severity:{result.get('severity')}")
                    print(f"\t | metadata:{result.get('metadata')}")
                    print(f"\t | query:{result.get('query')}")
                    print(f"\t | jarm_hash:{result.get('jarm_hash')}")
                    hml_c2_list.append(html_)
        print('----------------------------------------------\n')

        SaveFile().generate_html_report_c2(filename=file_names, command_and_control_html=hml_c2_list,
                                           gogo_scan_html=code_data['data'][1])
        SaveFile().file_gogo_txt(file_names, code_data['data'][1])
        SaveFile().file_c2_txt(file_names, hml_c2_list)
