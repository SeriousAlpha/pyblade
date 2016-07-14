#!env python
#coding = utf-8
import sys
import os

def list_file(filename2):
    cmd = "cat " + filename2
    cat = 'list'
    print cmd

    def demo(filename4):
        cmd = "cat " + filename4
        print cmd
        os.system(filename4)

    demo(cmd)

def cat_file(filename1):
    cmd = "cat " + filename1
    print cmd

    list_file(cmd)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "Usage: ./%s filename" % sys.argv[0]
        sys.exit(-1)

    file = "~/" + sys.argv[1]
    print file
    cat_file(file)

    sys.exit(0)

# file -> filename -> cmd -> filename -> cmd -> filename -> cmd  == os.system(cmd)

# catfile() -> listfile() -> demo()