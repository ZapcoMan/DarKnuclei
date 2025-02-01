# coding:utf-8
import time
import hmac
import hashlib
import base64
import urllib.parse
import requests
import logging.handlers
import os
import inspect
import configparser
import traceback


class DarkLog:
    """
    DarkLog : 用于日志的返回，和钉钉记录响应。
    """
    def __init__(self):
        """
        功能描述: 初始化日志位置，以及日志等级,日志调用
        参数:
        返回值:
        异常描述:
        调用演示:
        调用
        DarkLog().logger.info()

        实例化调用
        darklog = DarkLog()
        darklog.logger.debug("调式")
        darklog.logger.error(darklog.get_error_()) # 错误详细信息
        """
        frame = inspect.stack()[1]
        caller_filename = os.path.basename(frame.filename)
        self.logger = logging.getLogger(caller_filename)
        directory = 'log_'
        if not os.path.exists(directory):
            os.makedirs(directory)
        if not os.path.exists("project"):
            os.makedirs("project")
        if not os.path.exists("tmp"):
            os.makedirs("tmp")
        log_file = os.path.join(directory, "darklog.log")
        handler = logging.handlers.TimedRotatingFileHandler(
            log_file, when="W0", interval=1, backupCount=3, encoding="utf-8"
        )
        handler.setLevel(logging.NOTSET)

        formatter = logging.Formatter(
            "%(asctime)s || %(levelname)s  ||  %(name)s  || %(message)s || %(pathname)s %(lineno)d",
            datefmt="%Y-%m-%d %H:%M"  # 时间格式：精确到分钟
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)

    @staticmethod
    def get_error_():
        """
        :return: 详细异常信息
        """
        return traceback.format_exc()

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
        config = configparser.ConfigParser()
        config.read('config.ini')
        sections = config.sections()
        for section in sections:  # 循环[n+1]
            options = config.options(section)
            for option in options:  # 循环详细的字段
                value = config.get(section, option)
                if value_name == option:
                    return value

    def get_dingding(self, title_="", text_=""):
        """
        功能描述: 用于记录钉钉的通知
        参数:
            text_ : 钉钉通知标题
            title_ : 钉钉通知内容
        返回值:
            {"code": 404, "data": "配置文件为空,跳过钉钉通知"}
            {"code": 200, "data": dingding_}  返回钉钉状态码
            {"code": 500, "data": e}
        异常描述:
            {"code": 404, "data": "配置文件为空,跳过钉钉通知"}
            {"code": 200, "data": dingding_}  返回钉钉状态码
            {"code": 500, "data": e}
        调用演示:
            proxylog = ProxyLog()
            proxylog.get_dingding("测试标题", "这个是测试内容")
        """
        timestamp = str(round(time.time() * 1000))
        dingding_secret = self.get_config('dingding_secret')
        dingding_access_token = self.get_config('dingding_access_token')
        dingding_userid = self.get_config('dingding_userid')
        if dingding_secret == '' or dingding_access_token == '' or dingding_userid == '':
            self.logger.error(f"配置文件为空,跳过钉钉通知")
            return {"code": 404, "data": "配置文件为空,跳过钉钉通知"}
        secret_enc = dingding_secret.encode('utf-8')
        string_to_sign = '{}\n{}'.format(timestamp, dingding_secret)
        string_to_sign_enc = string_to_sign.encode('utf-8')
        hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))

        url = f"https://oapi.dingtalk.com/robot/send?access_token={dingding_access_token}&timestamp={timestamp}&sign={sign}"
        data = {
            "msgtype": "markdown",
            "markdown": {
                "title": title_,
                "text": f"@{dingding_userid}{text_}"
            },
            "at": {
                "atUserIds": [
                    dingding_userid
                ],
                "isAtAll": False
            }
        }
        try:
            dingding_ = requests.post(url, json=data).json()
            if dingding_["errcode"] == 300005 or dingding_["errcode"] == 310000:
                self.logger.info({"code": 403, "data": dingding_})
                return {"code": 403, "data": dingding_}
            self.logger.info(f"Request title: {title_} text:{text_}")
            self.logger.info(f"Response {dingding_}")
            return {"code": 200, "data": dingding_}
        except Exception as e:
            self.logger.error({"code": 500, "data": e})
            return {"code": 500, "data": e}
