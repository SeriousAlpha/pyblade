# !env python
# coding=utf-8
#
import utils.dump_python
import json
import os
import dis
import sys

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


#print 'lineno34', function_body.func_code.co_names
#print 'lineno35', function_body.func_code.co_varnames
#print dis.dis(function_body)

dir = os.path.abspath('..')
file = os.path.join(dir, 'tests\\sample2.py')
fd = open(file, 'r+')
strings = fd.read()

files = {
    'taintanalysis.py': strings}

for name, lines in files.iteritems():
    tree = utils.dump_python.parse_json_text(name, lines)
    tree = json.loads(tree)
    rec_decrease_tree(tree)
    filename = tree.get("filename")
    body = tree.get("body")
    print body
for key, value in tree.iteritems():
    print key, value

name = OrderedDict({})
i = 0
#for obj in body:
    #i = i + 1
    #print i
    #names = get_function_summary(obj)
    #print names

parent_path = os.path.abspath('..')
for keys in files.viewkeys():
    print keys

#fn = os.path.join(parent_path, keys)
#print fn

#for objs, content in obj.iteritems():
#    print objs, content

