# !env python
# coding=utf-8
#
#
#      functiondef.py
#
#      Copyright (C)  2015 - 2016 revised by Yong Huang <huangyong@iscas.ac.cn>
#
#      This program is free software; you can redistribute it and/or modify
#      it under the terms of the GNU General Public License as published by
#      the Free Software Foundation; either version 2 of the License, or
#      (at your option) any later version.
#
#      This program is distributed in the hope that it will be useful,
#      but WITHOUT ANY WARRANTY; without even the implied warranty of
#      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#      GNU General Public License for more details.
#
#      You should have received a copy of the GNU General Public License
#      along with this program; if not, write to the Free Software
#      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#      MA 02110-1301, USA.

import uuid
import os
import json
import utils.dump_python
import utils.color_log
import logging
import pprint

from collections import defaultdict
from collections import OrderedDict

logger = utils.color_log.init_log(logging.DEBUG)

dir = os.path.abspath('..')
file = os.path.join(dir, 'tests', 'sample2.py')
fd = open(file, 'r+')
strings = fd.read()
files = {
    'sample2.py': strings}


def gennerate_uuid(rootname, lineno):
    name = rootname + str(lineno)
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


def get_tree(file):
    for name, lines in file.iteritems():
        tree = utils.dump_python.parse_json_text(name, lines)
        tree = json.loads(tree)
        rec_decrease_tree(tree)
    return tree


def find_function(content, func_trees, rootname, origin_node):
    for body in content:
        if body.get('type') == 'FunctionDef':
            key = body.get('name')
            lineno = body.get('lineno')
            functionID = gennerate_uuid(rootname, lineno)
            newnode = origin_node[:]
            newnode.append(lineno)
            setInDict(func_trees, newnode, {'key': functionID, 'name': key})
            find_function(body.get('body'), func_trees, rootname, newnode)


def tree():
    return defaultdict(tree)


def dicts(t):
    try:
        return dict((k, dicts(t[k])) for k in t)
    except TypeError:
        return t


def getFromDict(dataDict, mapList):
    #return reduce(lambda d, k: d[k], mapList, dataDict)
    for k in mapList:
        dataDict = dataDict[k]
    return dataDict


def setInDict(dataDict, mapList, value):
    for k in mapList[:-1]:
        dataDict = dataDict[k]
    dataDict[mapList[-1]] = value


def find_function_call(content, detail_func, root_name):
    for body in content:
        if body.get('type') == 'Expr':
            call_lineno = body.get('lineno')
            call_name = (body.get('value').get('func').get('id') == None and body.get('value').get('func').get('value').get('id') or body.get('value').get('func').get('id'))
            call_funcID = gennerate_uuid(root_name, call_lineno)
            print call_name, call_funcID
        if body.get('type') == 'FunctionDef':
            func_name = body.get('name')
            lineno = body.get('lineno')
            funcID = gennerate_uuid(root_name, lineno)
            detail_func.setdefault(funcID, {'name': func_name, 'key': lineno})
            find_function_call(body.get('body'), detail_func, root_name)


def get_call_funcname(func):
    pass


def print_find_function(content):
    for body in content:
        if body.get('type') == 'FunctionDef':
            key = body.get('name')
            logger.warning('%s',key)
            print_find_function(body.get('body'))


def list_import(content):
    for body in content:
        if body.get('type') == 'Import':
            for name in body.get('names'):
                module_name = name.get('name')


def main():
    trees = get_tree(files)
    filename = trees.get('filename')
    parent_path = os.path.abspath('..')
    root_name = os.path.join(parent_path, 'test', filename)
    body = trees.get('body')
    func_tree = tree()
    detail_func = OrderedDict({})
    find_function(body, func_tree, root_name, [root_name])
    find_function_call(body, detail_func, root_name)
    pp = pprint.PrettyPrinter(depth=10)
    pp.pprint(dicts(func_tree))
    pp.pprint(dicts(detail_func))


if __name__ == "__main__":
    main()


# tpye : ClassDef, FunctionDef, Assign, If, Import, Attribute, Return