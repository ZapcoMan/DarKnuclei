# 🚀DarKnuclei

## 目录
- [简介](#简介)
- [功能](#功能)
- [使用场景](#使用场景)
- [特征覆盖](#特征覆盖)
   - [平台/服务](#平台服务)
   - [C2](#c2)
- [使用方法](#使用方法)
   - [环境配置](#环境配置)
   - [命令行使用](#命令行使用)
- [优先内测](#优先内测)
- [TODO](#todo)
- [关于/演示](#关于演示)

## 简介
DarKnuclei 是一款专为红蓝对抗设计的工具，不仅能够快速对目标进行打点，还能够扫描红队的基础设施与服务。该工具采用强/弱特征识别方法，通过特定的特征值来识别红队的C2（命令与控制）基础设施，内置`yaml`语法，用户可以自行编写`yaml`文件以识别特定的C2。
* 这个仓库本身就是 原本你的源码 创建出来的 原本的源码的压缩包中没有合适的requirements.txt 而我弄得这个仓库 可以直接使用 ```pip install -r  requirements.txt``` 来安装依赖。
## 功能
1. **快速打点**：对目标的测绘资产和网络服务进行快速扫描和识别。
2. **批量打点**：支持对大量目标进行快速扫描和识别。
3. **扫描红队基础设施与服务**：通过强/弱特征识别方法，识别红队的C2基础设施和其他服务。

## 使用场景
- **红队视角**：快速对目标进行打点和扫描，识别关键资产和漏洞。
- **蓝队视角**：扫描红队的基础设施和服务，帮助防御者了解和应对潜在威胁。

## 特征覆盖
### 强特征
- 支持对多种平台和服务的强特征识别，包括ARL、Scope Sentry、NPS、AWVS、Nessus等。
### 弱特征
- 支持对部分平台和服务的弱特征识别，包括JNDI-Injection-Exploit、rogue-jndi等。

## C2支持
- 支持对多种C2框架的识别，包括vshell、Cobalt Strike、Metasploit、Supershell、Viper等。

## 使用方法
### 环境配置
1. **安装依赖**：确保安装了所有必要的依赖项，如nuclei、nuclei-templates等。
2. **配置文件**：修改`config.ini`文件，添加必要的key和配置项。
3. **Python版本**：推荐使用`python3.9`。
4. **下载插件**：如果是mac或linux系统，请下载相应的执行程序到plugin目录，并配置`config.ini`。
5. 如果是mac或linux请下载对于的执行程序在plugin目录，并配置`config.ini`。
   1. [observer_ward](https://github.com/emo-crab/observer_ward)
   2. [gogo](https://github.com/chainreactors/gogo)
   3. [tlsx](https://github.com/projectdiscovery/tlsx)

# 特征覆盖
✅	强特征

☑️	弱特征
## 平台/服务
| 名字                        | 类型     | 特征 | 计划中 | 备注                              |
| --------------------------- | -------- | ---- | ------ | --------------------------------- |
| ARL(灯塔)                   | platform | ✅    |        |                                   |
| Scope Sentry                | platform | ✅    |        |                                   |
| NPS                         | platform | ✅    |        |                                   |
| AWVS                        | platform | ✅    |        |                                   |
| Nessus                      | platform | ✅    |        |                                   |
| XSS平台                     | platform | ✅    |        |                                   |
| BeEF                        | platform | ✅    |        |                                   |
| H                           | platform | ✅    |        |                                   |
| LangSrcCurise               | platform | ✅    |        |                                   |
| Medusa                      | platform | ✅    |        |                                   |
| NextScan                    | platform | ✅    |        |                                   |
| prismx                      | platform | ✅    |        |                                   |
| CyberEdge                   | platform | ✅    |        |                                   |
| SerializedPayloadGenerator  | platform | ✅    |        |                                   |
| web-chains                  | platform | ✅    |        |                                   |
| RevSuit                     | platform | ✅    |        |                                   |
| MemShellParty               | platform | ✅    |        |                                   |
| vulfocus                    | platform | ✅    |        |                                   |
| gophish                     | platform | ✅    |        |                                   |
| testnet                     | platform | ✅    |        |                                   |
| rengine                     | platform | ✅    |        |                                   |
| JNDI-Injection-Exploit-Plus | Tools    | ✅    |        | 只针对ldap强特征，rmi,jetty弱特征 |
| JNDI-Injection-Exploit      | Tools    | ✅    |        | 只针对ldap强特征，rmi,jetty弱特征 |
| rogue-jndi                  | Tools    | ✅    |        | 只针对ldap强特征，rmi,jetty弱特征 |
| JNDIMap                     | Tools    | ✅    |        | 只针对ldap强特征，rmi,jetty弱特征 |
| ysoserial                   | Tools    |      | ✔️      |                                   |

## C2
| 名字           | 版本        | 登录/连接 | 监听端口 | UDP流量 | TCP流量 | HTTP/S流量 | 计划中 | 备注 |
| -------------- | ----------- | --------- | -------- | ------- | ------- | ---------- | ------ | ---- |
| vshell         | 4.9.3~4.6.0 |           | ✅        | ✅       | ✅       | ✅          |        |      |
| Cobalt Strike  |             | ✅         |          |         |         | ✅          |        |      |
| Metasploit     |             |           |          |         | ✅       | ✅          |        |      |
| Supershell     | 2.0.0       | ✅         | ✅     |         |         |            |        |      |
| Viper          |             | ✅        |          |         | ☑️        |            | ✔️      |      |
| Daybreak       |             |           |          |         |         |            | ✔️      |      |
| chisel         |             |           |          |         |         |            | ✔️      |      |
| sliver         |             |           |          |         |         |            | ✔️      |      |
| Havoc          |             |           |          |         |         |            | ✔️      |      |
| Iom            |             |           |          |         |         |            | ✔️      |      |
| Villain        |             |           |          |         |         |            | ✔️      |      |
| VenomRA        |             |           |          |         |         |            | ✔️      |      |
| ShadowPad      |             |           |          |         |         |            | ✔️      |      |
| Shad0w         |             |           |          |         |         |            | ✔️      |      |
| Remcos RAT     |             |           |          |         |         |            | ✔️      |      |
| QuasarRAT      |             |           |          |         |         |            | ✔️      |      |
| Pupy-C2        |             |           |          |         |         |            | ✔️      |      |
| PoshC2         |             |           |          |         |         |            | ✔️      |      |
| PlugX RAT      |             |           |          |         |         |            | ✔️      |      |
| Orcus-RAT      |             |           |          |         |         |            | ✔️      |      |
| Ninja          |             |           |          |         |         |            | ✔️      |      |
| Mythic         |             |           |          |         |         |            | ✔️      |      |
| Havoc          |             |           |          |         |         |            | ✔️      |      |
| Hak5 Cloud     |             |           |          |         |         |            | ✔️      |      |
| Gh0st          |             |           |          |         |         |            | ✔️      |      |
| Empire         |             |           |          |         |         |            | ✔️      |      |
| DeimosC2       |             |           |          |         |         |            | ✔️      |      |
| DcRAT          |             |           |          |         |         |            | ✔️      |      |
| Covenant       |             |           |          |         |         |            | ✔️      |      |
| Brute Ratel C4 |             |           |          |         |         |            | ✔️      |      |
| BitRAT         |             |           |          |         |         |            | ✔️      |      |
| AsyncRAT       |             |           |          |         |         |            | ✔️      |      |
| manjusaka      |             |           |          |         |         |            | ✔️      |      |




### 命令行使用
~~~bash
>python39 main.py -h


    .__       .  .         .    
    |  \ _.._.|_/ ._ . . _.| _ *
    |__/(_][  |  \[ )(_|(_.|(/,| 
    DarKnuclei Beta v2.0 by RuoJi
        
usage: main.py [-h] {NSM,WEB,GOGO,RTSCAN} ...

positional arguments:
  {NSM,WEB,GOGO,RTSCAN}
                        主命令帮助
    NSM                 测绘资产
    WEB                 WEB扫描
    GOGO                GOGO扫描
    RTSCAN              扫描红队基础设施与服务

options:
  -h, --help            show this help message and exit

~~~
- `NSM`：测绘资产
- `WEB`：WEB扫描
- `GOGO`：GOGO扫描
- `RTSCAN`：扫描红队基础设施与服务

## 优先内测
提交平台或C2或服务等至issue进行审核，通过后可加入内测群。提交格式：ARL，Asset Reconnaissance Lighthouse，https://github.com/xxxx/ARL

## TODO：

- [ ] 搜索引擎js文件路径，以及ico图片hash搜索【手动导入，输入ico图标地址在线搜索】。
- [ ] 导出格式Excel报表。
- [ ] 对蜜罐识别进行识别调研，以及安全设备指纹。
- [ ] 针对其它资产测绘平台。
- [ ] 通过测绘得到IP资产，对IP资产进行端口扫描指纹识别。
- [ ] 钉钉企业微信漏洞扫描结果通知。
- [ ] 覆盖国内外C2。
- [ ] 编写`yaml`文件编写教程
- [ ] 编写调试模式

## 关于/演示
关于 DarKnuclei，DarKnuclei专注于红蓝对抗一款工具，不仅可以扫描漏洞，快速打点，还可以扫描红队基础设施与服务，拥有高扩展的yaml格式指纹文件，方便自己编写红队基础设施指纹。

![image](https://github.com/user-attachments/assets/f585eabe-b85c-4350-838e-e3296d0c1e4a)
![image](https://github.com/user-attachments/assets/93cc0b5a-cf11-4b84-b161-3c1d33719624)
![image](https://github.com/user-attachments/assets/32d09dfc-d96b-4945-928c-d0a1f6aa5a74)

