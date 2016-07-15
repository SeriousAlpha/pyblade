# !env python
# coding=utf-8
#
#      main.py
#
#      Copyright (C) 2014 - 2015 https://github.com/shengqi158/pyvulhunter is origin
#
#                   2015 - 2016 revised by Yong Huang <huangyong@iscas.ac.cn>
#
#      This program is free software; you can redistribute it and/or modify
#      it under the terms of the GNU General Public License as published by
#      the Free Software Foundation; either version 2 of the License, or
#      (at your option) any later version.
#
#      This program is distributed in the hope that it will be useful,
#      but WITHOUT ANY WARRANTY; without even the implied warranty of
#      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#      GNU General Public License for more details.
#
#      You should have received a copy of the GNU General Public License
#      along with this program; if not, write to the Free Software
#      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#      MA 02110-1301, USA.

from pyblade.analyser.TaintAnalysers import TaintAnalyzer

def usage():
    print """用途：本程序主要用于测试py代码中命令注入\n用法：python main.py -d path
        path即为需要测试的目录路径"""

def main():
    files = {
        'taintanalysis.py': '#!env python\n#coding = utf-8\nimport sys\nimport os\n\ndef list_file(filename2):\n    cmd = "cat " + filename2\n    cat = \'list\'\n    print cmd\n\n    def demo(filename4):\n        cmd = "cat " + filename4\n        print cmd\n        demostate(filename4)\n        os.system(filename4)\n\n    demo(cmd)\n\ndef demostate(filename3):\n    os.system(filename3)\n\ndef cat_file(filename1):\n    cmd = "cat " + filename1\n    print cmd\n\n    list_file(cmd)\n\nif __name__ == \'__main__\':\n    if len(sys.argv) < 2:\n        print "Usage: ./%s filename" % sys.argv[0]\n        sys.exit(-1)\n\n    file = "~/" + sys.argv[1]\n    print file\n    cat_file(file)\n\n    sys.exit(0)\n\n# file -> filename -> cmd -> filename -> cmd -> filename -> cmd  == os.system(cmd)\n\n# catfile() -> listfile() -> demo()'}
    scan(files)

def scan(files):
    for name, lines in files.iteritems():
        propagation = TaintAnalyzer(name,  lines)
        propagation.parse_py()
        ret = propagation.source_to_sink()
        propagation.record_all_func()
        print ret
    return not ret

if __name__ == "__main__":

    main()

