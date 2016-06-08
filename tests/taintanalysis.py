#!env python
#coding = utf-8
#import sys
#import os

def cat_file(filename):
    cmd = "cat " + filename
    print cmd

    #os.system(cmd)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "Usage: ./%s filename" % sys.argv[0]
        sys.exit(-1)

    file = sys.argv[1] + "~/"
    print file
    cat_file(file)

    sys.exit(0)
