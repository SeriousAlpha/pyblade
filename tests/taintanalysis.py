#!env python
#coding = utf-8
import sys
import os


def list_file(filename2):
    cmd = "cat " + filename2

    def demo(filename4):
        cmd1 = "cat " + filename4
        os.system(cmd1)
    demo(cmd)


def cat_file(filename1):
    cmd = "cat " + filename1
    list_file(cmd)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "Usage: ./%s filename" % sys.argv[0]
        sys.exit(-1)
    files = "~/" + sys.argv[1]

    cat_file(files)
    sys.exit(0)

# file -> filename -> cmd -> filename -> cmd -> filename -> cmd  == os.system(cmd)

