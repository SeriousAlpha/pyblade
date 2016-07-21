
files = {
    'taintanalysis.py':'#!env python\n#coding = utf-8\nimport sys\nimport os\n\ndef list_file(filename2):\n    cmd = "cat " + filename2\n    cat = \'list\'\n    print cmd\n\n    def demo(filename4):\n        cmd = "cat " + filename4\n        print cmd\n        for i in range(3):\n            os.system(\'cat\')\n        demo(cmd)\n\n    demo(cmd)\n\ndef demostate(filename3):\n    os.system(filename3)\n\ndef cat_file(filename1):\n    cmd = "cat " + filename1\n    print cmd\n    os.system(filename1)\n    eval(filename1)\n    list_file(cmd)\n\nif __name__ == \'__main__\':\n    if len(sys.argv) < 2:\n        print "Usage: ./%s filename" % sys.argv[0]\n        sys.exit(-1)\n\n    file = "~/" + sys.argv[1]\n    print file\n    cat_file(file)\n\n    sys.exit(0)\n\n# file -> filename -> cmd -> filename -> cmd -> filename -> cmd  == os.system(cmd)\n\n# catfile() -> listfile() -> demo()'}

from pyblade import scan

res = scan(files)
print res
