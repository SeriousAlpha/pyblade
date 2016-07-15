
import dump_python
import json
import os
from collections import defaultdict
from collections import OrderedDict

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

def get_function_summary(obj):
    function = {}
    if obj.get("type") == "FunctionDef":
        func_name = obj.get('name')
        lineno = obj.get('lineno')
        for arg in obj.get('args').get('args'):
            arg_ori = arg.get('id')
        function.setdefault(lineno, []).append(arg_ori)
        return function

def function_body(func_name):
    if obj.get("name") == func_name:
        print obj.get('body')

files = {
    'taintanalysis.py': '#!env python\n#coding = utf-8\nimport sys\nimport os\n\ndef list_file(filename2):\n    cmd = "cat " + filename2\n    cat = \'list\'\n    print cmd\n\n    def demo(filename4):\n        cmd = "cat " + filename4\n        print cmd\n        demostate(filename4)\n        os.system(filename4)\n\n    demo(cmd)\n\ndef demostate(filename3):\n    os.system(filename3)\n\ndef cat_file(filename1):\n    cmd = "cat " + filename1\n    print cmd\n\n    list_file(cmd)\n\nif __name__ == \'__main__\':\n    if len(sys.argv) < 2:\n        print "Usage: ./%s filename" % sys.argv[0]\n        sys.exit(-1)\n\n    file = "~/" + sys.argv[1]\n    print file\n    cat_file(file)\n\n    sys.exit(0)\n\n# file -> filename -> cmd -> filename -> cmd -> filename -> cmd  == os.system(cmd)\n\n# catfile() -> listfile() -> demo()'}

for name, lines in files.iteritems():
    tree = dump_python.parse_json_text(name, lines)
    tree = json.loads(tree)
    rec_decrease_tree(tree)
    filename = tree.get("filename")
    body = tree.get("body")
#for key,value in tree.iteritems():
#    print key, value

name = OrderedDict({})
i = 0
for obj in body:
    i = i + 1
    print i
    names = get_function_summary(obj)
    print names


parent_path = os.path.abspath('..')
for keys in files.viewkeys():
    print keys
fn = os.path.join(parent_path, keys)
print fn

#    for objs, content in obj.iteritems():
        #pass
#        print objs, content

