 Python Security
============
 Source Code Auto Audit
----------------------

### 基本原理：
    污点分析有三大元素，敏感源、敏感规则、敏感宿，敏感源主要分两类，污点是指来自程序外部输入的数据(如秘密数据或恶意数据)
    
### 实现方法：
    先利用dump_python文件对Python源代码进行字典化保存，然后

### 用法：
1. 在Python 命令行模式下，输入python main.py -d *path*\test  path为当前绝对目录
2. 在eclipse+pydev环境下，run->run configurations->Arguments 填入-d *path*\test path为当前绝对目录
3. 在pycharm环境下，在run->debug configurations->script parameters填入-d *path*\test path为当前绝对目录     
在集成开发环境下，run一下main.py文件

### 文件说明：
* colorlog.py 用于对log进行着色
* dump_python.py 对Python进行语法树分析,把源文件转成一个字典保存