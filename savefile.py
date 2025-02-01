import json
from datetime import datetime
from dark_log import DarkLog
from print_color import Colorpr
import jinja2

darklog = DarkLog()


class SaveFile:
    """
    SaveFile : 处理保存文件信息
    """

    @staticmethod
    def formatted_time():
        """
        功能描述: 返回系统当前时间 time:2024-12-07 19:15:31
        参数:
        返回值:
        异常描述:
        调用演示:
            time_data = self.formatted_time()
        """
        # 获取当前时间
        now = datetime.now()
        # 定义时间格式
        time_format = "%Y-%m-%d %H:%M:%S"
        # 按照定义的格式对当前时间进行格式化
        return str(now.strftime(time_format))

    @staticmethod
    def replace_txt(data):
        return data.replace('http://', '').replace('https://', '').replace('/', '').replace('.', '_').replace(':',
                                                                                                              '_').replace(
            '-', '_').replace(' ', '_')

    def file_cyberspace_txt(self, filename, filedata):
        """
        功能描述: 保存黑暗搜索引擎出来的结果为txt文件
        参数:
            filename : 保存的文件名
            filedata : 保存的文件内容 ['数组']
        返回值:
        异常描述:
        调用演示:
            sc = SaveFile().file_cyberspace_txt("baidu.com", ["数组"])
        """
        if filedata['code'] != 200:
            print(Colorpr.color_blue_bd("No Cyberspace Mapping"))
            darklog.logger.warning(filedata)
        else:
            # unique_arr = []
            # if filedata['data'] is not None and len(filedata['data']) > 0:  # 去重
            #     unique_arr = []
            #     seen = set()
            #     # 过滤掉空字符串
            #     filtered_batch = [item for item in filedata['data'] if item != '']
            #     for item in filtered_batch:
            #         if item not in seen:
            #             unique_arr.append(item)
            #             seen.add(item)
            # print(Colorpr.color_red_bd(unique_arr))  # fofa查询出来的数据打印

            filename = self.replace_txt(filename)
            filename = 'project/' + filename
            with open(filename + '.txt', 'a+', encoding='utf-8') as f:
                darklog.logger.info("Save the cyberspace file: " + filename + '.txt')
                print(Colorpr.color_red_bd("Save the cyberspace file: " + filename + '.txt'))
                f.write(f'>----------     [搜索结果 time:{self.formatted_time()}]     ----------<\n')
                for i in filedata['data']:
                    if i != "":
                        f.write(str(i) + '\n')

    def file_gogo_txt(self, filename, filedata):
        """
        功能描述: 保存gogo出来的结果为txt文件
        参数:
            filename : 保存的文件名
            filedata : 保存的文件内容 ['数组']
        返回值:
        异常描述:
        调用演示:
            sc = SaveFile().file_cyberspace_txt("baidu.com", ["数组"])
        """
        filename = self.replace_txt(filename)
        filename = 'project/' + filename
        with open(filename + '.txt', 'a+', encoding='utf-8') as f:
            darklog.logger.info("Save the gogo file: " + filename + '.txt')
            print(Colorpr.color_red_bd("Save the gogo file: " + filename + '.txt'))
            f.write(f'>----------     [gogo结果 time:{self.formatted_time()}]     ----------<\n')
            for i in filedata:
                for key, value in i.items():
                    if value != "":
                        if key != 'frameworks':
                            f.write(str(key) + ": " + str(value) + '\n')
                        else:
                            f.write(str(key) + ":  " + str(value) + '\n')
                f.write('\n')

    def file_c2_txt(self, filename, filedata):
        """
        功能描述: 保存c2出来的结果为txt文件
        参数:
            filename : 保存的文件名
            filedata : 保存的文件内容 ['数组']
        返回值:
        异常描述:
        调用演示:
            sc = SaveFile().file_cyberspace_txt("baidu.com", ["数组"])
        """
        filename = self.replace_txt(filename)
        filename = 'project/' + filename
        with open(filename + '.txt', 'a+', encoding='utf-8') as f:
            darklog.logger.info("Save the c2 file: " + filename + '.txt')
            print(Colorpr.color_red_bd("Save the c2 file: " + filename + '.txt'))
            f.write(f'>----------     [溯源结果 time:{self.formatted_time()}]     ----------<\n')
            for i in filedata:
                f.write('\n')
                for key, value in i.items():
                    f.write(str(key) + ":  " + str(value) + '\n')

    def file_observer_ward_txt(self, filename, filedata):
        """
        功能描述: 保存指纹扫描出来的结果为txt文件
        参数:
            filename : 保存的文件名
            filedata : 保存的文件内容 ['数组']
        返回值:
        异常描述:
        调用演示:
            sc = SaveFile().file_observer_ward_txt("baidu.com", ["数组"])
        """
        if filedata['code'] != 200:
            print(Colorpr.color_blue_bd("No fingerprint"))
            darklog.logger.warning(filedata)
        else:
            filename = self.replace_txt(filename)
            filename = 'project/' + filename
            with open(filename + '.txt', 'a+', encoding='utf-8') as f:
                darklog.logger.info("Save the observer file: " + filename + '.txt')
                print(Colorpr.color_red_bd("Save the observer file: " + filename + '.txt'))
                f.write(f'\n>----------     [指纹结果 time:{self.formatted_time()}]     ----------<\n')
                for i in filedata['data']:
                    f.write('\n')
                    for i_ in i:
                        for key, value in i_.items():
                            f.write(str(key) + ": " + str(value) + '\n')

    def file_nuclei_txt(self, filename, filedata):
        """
        功能描述: 保存漏洞扫描的结果为txt文件
        参数:
            filename : 保存的文件名
            filedata : 保存的文件内容 ['数组']
        返回值:
        异常描述:
        调用演示:
            sc = SaveFile().file_nuclei_txt("baidu.com", ["数组"])
        """
        if filedata['code'] != 200:
            darklog.logger.warning(filedata)
            print(Colorpr.color_blue_bd("No poc"))
        else:
            filename = self.replace_txt(filename)
            filename = 'project/' + filename
            with open(filename + '.txt', 'a+', encoding='utf-8') as f:
                darklog.logger.info("Save the nuclei file: " + filename + '.txt')
                print(Colorpr.color_red_bd("Save the nuclei file: " + filename + '.txt'))
                f.write(f'\n>>------->>     [漏洞结果 time:{self.formatted_time()}]     <<-------<<\n')

                for i in filedata['data']:
                    f.write('\n')
                    for key, value in i.items():
                        if str(key).strip() != "":
                            f.write(str(key).strip() + ": " + str(value) + '\n')
                        else:
                            f.write(str(value) + '\n')

    def generate_html_report(self, filename, cyberspace_search_html=None, gogo_scan_html=None, observer_ward_html=None,
                             nuclei_scan_html=None):
        """
        功能描述: 保存所以结果为html文件
        参数:
            filename : 保存的文件名
            cyberspace_search_html : 测绘资产 ['数组']
            gogo_scan_html : gogo扫描资产 ['数组']
            observer_ward_html : 指纹识别 ['数组']
            nuclei_scan_html : nuclei扫描 ['数组']
        返回值:
        异常描述:
        调用演示:
                SaveFile().generate_html_report(filename=file_time, cyberspace_search_html=[],
                                    gogo_scan_html=code_data['data'][1],
                                    observer_ward_html=observer_ward_json_result['data'],
                                    nuclei_scan_html=nuclei_json_result['data'])
        """
        # 如果参数为 None，则赋予空数组
        cyberspace_search_html = cyberspace_search_html if cyberspace_search_html not in [None, ''] else []
        gogo_scan_html = gogo_scan_html if gogo_scan_html not in [None, ''] else []
        observer_ward_html = observer_ward_html if observer_ward_html not in [None, ''] else []
        nuclei_scan_html = nuclei_scan_html if nuclei_scan_html not in [None, ''] else []

        file_time = SaveFile.formatted_time()
        # 加载模板
        template_loader = jinja2.FileSystemLoader(searchpath="templates")
        template_env = jinja2.Environment(loader=template_loader)

        template = template_env.get_template("report_template.html")

        # 渲染模板
        output = template.render(
            time_time=file_time,
            cyberspace_search=cyberspace_search_html,
            gogo_scan=gogo_scan_html,
            observer_ward=observer_ward_html,
            nuclei_scan=nuclei_scan_html,
        )
        filename = self.replace_txt(filename)
        filename = 'project/' + filename + ".html"
        # 输出到 HTML 文件
        with open(filename, "w", encoding="utf-8") as f:
            f.write(output)
        print(Colorpr.color_red_bd(f"Save the html file: {filename}"))
        darklog.logger.info(f"Save the html file: {filename}")

    def generate_html_report_c2(self, filename, command_and_control_html=None, gogo_scan_html=None):
        """
        功能描述: 保存所以结果为html文件
        参数:
            filename : 保存的文件名
            cyberspace_search_html : 测绘资产 ['数组']
            gogo_scan_html : gogo扫描资产 ['数组']
            observer_ward_html : 指纹识别 ['数组']
            nuclei_scan_html : nuclei扫描 ['数组']
        返回值:
        异常描述:
        调用演示:
                SaveFile().generate_html_report(filename=file_time, cyberspace_search_html=[],
                                    gogo_scan_html=code_data['data'][1],
                                    observer_ward_html=observer_ward_json_result['data'],
                                    nuclei_scan_html=nuclei_json_result['data'])
        """
        # 如果参数为 None，则赋予空数组
        # command_and_control_html = command_and_control_html if command_and_control_html not in [None, ''] else []
        # gogo_scan_html = gogo_scan_html if gogo_scan_html not in [None, ''] else []

        file_time = SaveFile.formatted_time()
        # 加载模板
        template_loader = jinja2.FileSystemLoader(searchpath="templates")
        template_env = jinja2.Environment(loader=template_loader)

        template = template_env.get_template("report_template_c2.html")

        # 渲染模板
        output = template.render(
            time_time=file_time,
            command_and_control=command_and_control_html,
            gogo_scan=gogo_scan_html,
        )
        filename = self.replace_txt(filename)
        filename = 'project/' + filename + ".html"
        # 输出到 HTML 文件
        with open(filename, "w", encoding="utf-8") as f:
            f.write(output)
        print(Colorpr.color_red_bd(f"Save the html file: {filename}"))
        darklog.logger.info(f"Save the html file: {filename}")