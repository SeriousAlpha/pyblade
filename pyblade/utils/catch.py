
import dump_python
import json

def rec_decrease_tree(tree):
    if isinstance(tree, dict):
        for key in tree.keys():
            if key in ['col_offset', 'start', 'end', 'ctx', 'extra_attr', 'attr_name']:
                del(tree[key])
            else:
                if isinstance(tree[key], dict):
                    rec_decrease_tree(tree[key])
                if isinstance(tree[key], list):
                    for l in tree[key]:
                        rec_decrease_tree(l)

files = {
    'taintanalysis.py': '#!env python\n#coding = utf-8\nimport sys\nimport os\n\ndef list_file(filename):\n    cmd = "cat " + filename\n    cat = \'list\'\n    print cmd\n\n    def demo(filename):\n        cmd = "cat " + filename\n        print cmd\n        demostate(filename)\n        os.system(filename)\n\n    demo(cmd)\n\ndef demostate(filename):\n    os.system(filename)\n\ndef cat_file(filename):\n    cmd = "cat " + filename\n    print cmd\n\n    list_file(cmd)\n\nif __name__ == \'__main__\':\n    if len(sys.argv) < 2:\n        print "Usage: ./%s filename" % sys.argv[0]\n        sys.exit(-1)\n\n    file = "~/" + sys.argv[1]\n    print file\n    cat_file(file)\n\n    sys.exit(0)\n\n# file -> filename -> cmd -> filename -> cmd -> filename -> cmd  == os.system(cmd)\n\n# catfile() -> listfile() -> demo()'}

for name, lines in files.iteritems():
    tree = dump_python.parse_json_text(name, lines)
    tree = json.loads(tree)
    rec_decrease_tree(tree)
    filename = tree.get("filename")
    body = tree.get("body")
#for key,value in tree.iteritems():
#    print key, value
i = 0
for obj in body:
    global i
    i = i + 1
    print i
    print 'execute!'
    print obj
    if obj.get("type") == "FunctionDef":
        pass
#
#        for objs,content in obj.iteritems():
#            print objs,content
#print tree
#print filename,body

