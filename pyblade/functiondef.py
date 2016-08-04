# !env python
# coding=utf-8
#
#
import uuid
import os
import json
import utils.dump_python
import utils.color_log
import logging
import pprint

from collections import defaultdict

logger = utils.color_log.init_log(logging.DEBUG)


def gennerate_uuid(filename, lineno):
    name = filename + lineno
    return uuid.uuid3(uuid.NAMESPACE_DNS, name).hex


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


dir = os.path.abspath('..')
file = os.path.join(dir, 'tests', 'sample2.py')
fd = open(file, 'r+')
strings = fd.read()

files = {
    'sample2.py': strings}


def get_tree(file):
    for name, lines in file.iteritems():
        tree = utils.dump_python.parse_json_text(name, lines)
        tree = json.loads(tree)
        rec_decrease_tree(tree)
    return tree


def find_function(content, func_tree, path):
    for body in content:
        if body.get('type') == 'FunctionDef':
            key = body.get('name')
            lineno = body.get('lineno')
            newpath = path[:]
            newpath.append(key)
            add(func_tree, newpath)
            find_function(body.get('body'), func_tree, newpath)


def list_import(content):
    for body in content:
        if body.get('type') == 'Import':
            for name in body.get('names'):
                module_name = name.get('name')


def tree():
    return defaultdict(tree)


def dicts(t):
    try:
        return dict((k, dicts(t[k])) for k in t)
    except TypeError:
        return t


def add(t, keys):
    for key in keys:
        t = t[key]


def main():
    trees = get_tree(files)
    filename = trees.get('filename')
    parent_path = os.path.abspath('..')
    fn = os.path.join(parent_path, 'tests', filename)
    body = trees.get('body')
    func_tree = tree()
    find_function(body, func_tree, ['root'])
    pp = pprint.PrettyPrinter(depth=10)
    pp.pprint(dicts(func_tree))


if __name__ == "__main__":
    main()


# tpye : ClassDef, FunctionDef, Assign, If, Import, Attribute