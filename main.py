from scan import Scan
from dark_log import DarkLog
from cyberspace_search import Cyberspace
from savefile import SaveFile
from resultdata import ResultData
import argparse
from print_color import Colorpr
import re
import shutil
from run_def import NSM_subcommand, WEBSCAN_subcommand, GOGO_command, RTScan_command

darklog = DarkLog()

if __name__ == '__main__':
    print(Colorpr().color_title())
    parser = argparse.ArgumentParser(description="")
    subparsers = parser.add_subparsers(help="主命令帮助")

    # 测绘命令
    NSM_subparser = subparsers.add_parser('NSM', help='测绘资产')
    NSM_subparser.add_argument("-ip", "--ip", help="测绘ip", default=None)
    NSM_subparser.add_argument("-icp", "--icp", help="测绘icp备案信息", default=None)
    NSM_subparser.add_argument("-domain", "--domain", help="测绘域名", default=None)
    NSM_subparser.add_argument("-body", "--body", help="测绘网页正文关键字", default=None)
    NSM_subparser.add_argument("-title", "--title", help="测绘网页标题关键字", default=None)
    NSM_subparser.add_argument("-quake_size", "--quake_size", help="quake测绘结果，默认1k", default=1000)
    NSM_subparser.add_argument("-b", "--observer", help=Colorpr.color_red("指纹扫描"), action="store_true")
    NSM_subparser.add_argument("-n", "--nuclei", help=Colorpr.color_red("指纹+漏洞扫描"), action="store_true")
    # NSM_subparser.add_argument("-e", "--export", help="仅导出", action="store_true")
    NSM_subparser.add_argument("-ot", "--observer_thread", help="指纹识别多线程", default="20")
    NSM_subparser.add_argument("-na", "--nuclei_args", help="nuclei的额外参数 =\"-es info\"", default=None)
    NSM_subparser.add_argument("-np", "--proxy", help="扫描代理【socks5,http】", default=None)
    NSM_subparser.set_defaults(func=NSM_subcommand)

    # web扫描
    WEB_subparser = subparsers.add_parser('WEB', help='WEB扫描')
    WEB_subparser.add_argument("-b", "--observer", help=Colorpr.color_red("单个目标指纹扫描 [模块]"),
                               default=None)
    WEB_subparser.add_argument("-n", "--nuclei", help=Colorpr.color_red("单个目标指纹漏洞扫描 [模块]"),
                               default=None)
    WEB_subparser.add_argument("-bl", "--observer_file", help=Colorpr.color_red("批量目标指纹扫描 [模块]"),
                               default=None)
    WEB_subparser.add_argument("-nl", "--nuclei_file", help=Colorpr.color_red("批量目标指纹漏洞扫描 [模块]"),
                               default=None)
    WEB_subparser.add_argument("-ot", "--observer_thread", help="指纹识别多线程", default="20")
    WEB_subparser.add_argument("-na", "--nuclei_args", help="nuclei的额外参数 =\"-es info\"", default=None)
    WEB_subparser.add_argument("-np", "--proxy", help="扫描代理【socks5,http】", default=None)
    WEB_subparser.set_defaults(func=WEBSCAN_subcommand)

    # GOGO扫描
    GOGO_subparser = subparsers.add_parser('GOGO', help='GOGO扫描')
    GOGO_subparser.add_argument("-f", "--file", help="扫描文件", default=None)
    GOGO_subparser.add_argument("-i", "--ip", help="扫描指定ip", default=None)
    GOGO_subparser.add_argument("-p", "--gogo_port", help="gogo扫描指定端口", default='80,443,8080')
    GOGO_subparser.add_argument("-gt", "--gogo_thread", help="gogo线程，默认1000", default="1000")
    GOGO_subparser.add_argument("-ot", "--observer_thread", help="指纹识别多线程", default="20")
    GOGO_subparser.add_argument("-ev", "--gogo_poc", help="gogo自带漏洞验证", action="store_true")
    GOGO_subparser.add_argument("-b", "--observer", help=Colorpr.color_red("指纹扫描"), action="store_true")
    GOGO_subparser.add_argument("-n", "--nuclei", help=Colorpr.color_red("指纹+漏洞扫描"), action="store_true")
    GOGO_subparser.add_argument("-na", "--nuclei_args", help="nuclei的额外参数 =\"-es info\"", default=None)
    GOGO_subparser.add_argument("-np", "--proxy", help="扫描代理【socks5,http】", default=None)
    GOGO_subparser.set_defaults(func=GOGO_command)

    # RTScan
    RTSCAN_subparser = subparsers.add_parser('RTSCAN', help='扫描红队基础设施与服务')
    RTSCAN_subparser.add_argument("-f", "--file", help="扫描文件", default=None)
    RTSCAN_subparser.add_argument("-i", "--ip", help="扫描指定ip", default=None)
    RTSCAN_subparser.add_argument("-p", "--gogo_port", help="gogo扫描指定端口",
                                  default='22,80,443,3333,3443,5000,5003,8011,8888,8000,8082,60000')
    RTSCAN_subparser.add_argument("-gt", "--gogo_thread", help="gogo线程，默认1000", default="1000")
    # RTScan_subparser.add_argument("-ot", "--observer_thread", help="指纹识别多线程", default="20")
    RTSCAN_subparser.add_argument("-ev", "--gogo_poc", help="gogo自带漏洞验证", action="store_true")
    # RTScan_subparser.add_argument("-b", "--observer", help=Colorpr.color_red("指纹扫描"), action="store_true")
    RTSCAN_subparser.add_argument("-t", "--tags", help="扫描指定的tags", default=None)
    RTSCAN_subparser.add_argument("-fy", "--file_yaml", help="扫描指定的yaml文件", default=None)
    RTSCAN_subparser.add_argument("-a", "--all_yaml", help="查看可扫描的yaml", action="store_true")
    # RTScan_subparser.add_argument("-wp", "--web_proxy", help="web扫描代理【socks5,http】", default=None)
    RTSCAN_subparser.add_argument("-np", "--proxy", help="扫描代理【socks5,http】", default=None)
    RTSCAN_subparser.set_defaults(func=RTScan_command)

    # 解析命令行参数
    args = parser.parse_args()
    # 执行相应的子命令函数
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()
