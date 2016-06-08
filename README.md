 Python Security
============
 Source Code Auto Audit
----------------------

### 基本原理：
    污点分析有三大元素：敏感源、敏感规则、敏感宿。敏感源主要分两类，污点是指来自程序外部输入的数据(如秘密数据或恶意数据)，
    敏感源主要分两大类：第一、Python的命令行参数sys.argv[]，sys.argv[0]表示代码本身文件路径，所以可控参数的索引从1开始。
    第二，不安全的外部数据输入函数。如网络数据接收函数：web.input从网络获取数据,socket.read读取socket包,requests.get读取服务器响应的内容。
    还有如文件内容读取函数，路径读取函数等等。敏感规则就是争对安全漏洞的形成原理制定防范规则，敏感宿就是含有可控参数的执行危险函数的命令语句。
    
### 实现方法：
    先利用dump_python文件对Python源代码进行字典化保存，然后取相应的键和值，找到sys.argv所在的位置，标记污染源，然后分析敏感路径，最后找到敏感宿，形成污染分析的最终结果。

### 用法：
1. 在Python 命令行模式下，输入python main.py -d *path*\test  path为当前绝对目录
2. 在eclipse+pydev环境下，run->run configurations->Arguments 填入-d *path*\test path为当前绝对目录
3. 在pycharm环境下，在run->debug configurations->script parameters填入-d *path*\test path为当前绝对目录     
在集成开发环境下，run一下main.py文件

### 文件说明：
* colorlog.py 用于对log进行着色
* dump_python.py 对Python进行语法树分析,把源文件转成一个字典保存