#!env python
#coding = utf-8
import sys
import os

def list_file(filename):
    cmd = "cat " + filename
    cat = 'list'
    print cmd

    def demo(filename):
        cmd = "cat " + filename
        print cmd
        os.system(cmd)

    demo(cmd)
def cat_file(filename):
    cmd = "cat " + filename
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