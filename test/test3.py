#!env python
#coding=utf-8
#
import sys
import os

def test_def(self, s, fullname):
    s = """ (lambda fc=( lambda n: [c for c in ().__class__.__bases__[0].__subclasses__() if c.__name__ == n][0]):
    fc("function")(
        fc("code")(0,0,0,0,"test",(),(),(),"","",0,""),{})())()"""
    eval(s, {'__builtins__':{}})

    fullname = "authExport.dat"
    os.system('sudo rm -f %s'%fullname)

    if (isinstance(s,str)):
        print s
    elif(isinstance(fullname,str)):
        print fullname
    else:
        print "not str"

    i = 1


def cat_file(filename):
    cmd = "cat" + filename
    print cmd

    os.system(cmd)


def test_branch(self, path):
    path = "D:/githubsvn/cfgtraverser/src/file.py"
    i = 10
    if (isinstance(path,str)):
        print path
    else:
        print "not str"

#if __name__ == '__main__':
#    if len(sys.argv) < 2:
#        print "Usage: ./%s filename" % sys.argv[0]
#        sys.exit(-1)

#    file = "~/" + sys.argv[1]
#    cat_file(file)

#    sys.exit(0)