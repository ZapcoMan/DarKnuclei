import json
from dark_log import DarkLog
from print_color import Colorpr

darklog = DarkLog()


class ResultData:
    """
    ResultData : 用于处理observer_ward扫描结果
    """

    @staticmethod
    def scan_result(result_file):
        """
        功能描述:
            处理 observer_ward 和 nuclei 扫描结果文件，提取并格式化相关信息。
        参数:
            result_file : dict
                包含文件读取状态及文件路径信息的字典，结构如下：
                {
                    "code": int,  # 文件读取状态码，200 表示成功，其他表示失败
                    "data": str   # 文件路径
                }
        返回值:
            tuple:
                observer_ward_json_result : dict
                    {"code": 200, "data": observer_ward_list_} 处理成功，返回 observer_ward 数据列表
                    {"code": 404, "data": ""} 数据为空或文件读取失败
                nuclei_json_result : dict
                    {"code": 200, "data": nuclei_list_} 处理成功，返回 nuclei 数据列表
                    {"code": 404, "data": ""} 数据为空或文件读取失败
        日志:
        异常描述:
        调用演示:
            result = ResultData.scan_result({"code": 200, "data": "path_to_file.json"})
        """
        nuclei_json_result = {'code': 404, 'data': ''}
        observer_ward_json_result = {'code': 404, 'data': ''}
        if result_file['code'] != 200:
            darklog.logger.error(result_file)
            return observer_ward_json_result, nuclei_json_result
        else:
            with open(result_file['data'], 'r', encoding='utf-8') as f:
                observer_ward_list_ = []
                nuclei_list_ = []
                for i in f.readlines():
                    i = i.strip()
                    if len(json.loads(i)) != 0:
                        observer_ward_list = []
                        for key, value in json.loads(i).items():
                            # print(f"url: {key}")  # url
                            # print(f"title: {value['title']}")  # 标题
                            # print(f"status: {value['status']}")  # 状态
                            # print(f"favicon: {value['favicon']}")  # 图标
                            # print(f"name: {value['name']}")  # 指纹名
                            observer_ward_list.append({
                                'url': key,
                                'title': value['title'],
                                'status': value['status'],
                                'favicon': value['favicon'],
                                'name': value['name']
                            })
                            for key_ in value['fingerprints']:  # 指纹详细信息
                                observer_ward_list.append({
                                    key_['matcher-results'][0]['template']: key_['matcher-results'],
                                    # 'matcher-name': key_['matcher-results'][0]['matcher-name'],
                                    # 'tags': key_['matcher-results'][0]['info']['tags'],
                                })
                            observer_ward_list_.append(observer_ward_list)

                            nuclei_list = []
                            if len(value['nuclei']) != 0:
                                # print('\n---------------------nuclei------------------------------')
                                for key_ in value['name']:
                                    if len(value['nuclei'][key_]) != 0:
                                        # print(value['nuclei'][key_][0]['template-id'])  # 漏洞名
                                        # print(valuez['nuclei'][key_][0]['matched-at'])  # 匹配地址
                                        # print(value['nuclei'][key_][0]['info']['name'])  # 漏洞详细名
                                        # print(value['nuclei'][key_][0]['info']['tags'])  # 漏洞标签
                                        # print(value['nuclei'][key_][0]['info']['description'])  # 漏洞描述
                                        # print(value['nuclei'][key_][0]['info']['reference'])  # 漏洞参考
                                        # print(value['nuclei'][key_][0]['info']['severity'])  # 漏洞等级
                                        # print(value['nuclei'][key_][0]['curl-command'])  # payload shell
                                        for key_name in value['nuclei'][key_]:
                                            nuclei_list_.append({
                                                "information": str(key_name['template-id']),
                                                "name": str(key_name["info"]['name']),
                                                "URL": str(key_name['matched-at']),
                                                "severity": str(key_name["info"]['severity']),
                                                "detail": key_name
                                                # 'matched-at': str(value['nuclei'][key_][0]['matched-at']),
                                                # 'name-info': str(value['nuclei'][key_][0]['info']['name']),
                                                # 'tags': str(value['nuclei'][key_][0]['info']['tags']),
                                                # 'description': str(value['nuclei'][key_][0]['info']['description']),
                                                # 'reference': str(value['nuclei'][key_][0]['info']['reference']),
                                                # 'severity': str(value['nuclei'][key_][0]['info']['severity']),
                                                # 'curl-command': str(value['nuclei'][key_][0]['curl-command']),
                                            })
                if len(observer_ward_list_) != 0:
                    observer_ward_json_result = {'code': 200, 'data': observer_ward_list_}
                    darklog.logger.info(f"observer_ward quantity: {len(observer_ward_list_)}")
                    # print(f"observer_ward quantity: {len(observer_ward_list_)}")
                    print(Colorpr.color_red_bd(f"observer_ward quantity: {len(observer_ward_list_)}"))
                else:
                    observer_ward_json_result = {'code': 404, 'data': observer_ward_list_}
                if len(nuclei_list_) != 0:
                    nuclei_json_result = {'code': 200, 'data': nuclei_list_}
                    darklog.logger.info(f"nuclei poc: {len(nuclei_list_)}")
                    # print(f"nuclei poc quantity: {len(nuclei_list_)}")
                    print(Colorpr.color_red_bd(f"nuclei poc  quantity: {len(nuclei_list_)}"))
                else:
                    nuclei_json_result = {'code': 404, 'data': nuclei_list_}
                return observer_ward_json_result, nuclei_json_result
