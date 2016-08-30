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
from TaintAnalysers import rec_decrease_tree,get_func_id
logger = utils.color_log.init_log(logging.DEBUG)
pp = pprint.PrettyPrinter(depth=10)

dir = os.path.abspath('..')
file = os.path.join(dir, 'tests', 'sample2.py')
fd = open(file, 'r+')
strings = fd.read()
files = {
    'sample2.py': strings}


def gennerate_uuid(rootname, lineno):
    name = rootname + str(lineno)
    return uuid.uuid3(uuid.NAMESPACE_DNS, name).hex


def get_tree(file):
    for name, lines in file.iteritems():
        tree = utils.dump_python.parse_json_text(name, lines)
        tree = json.loads(tree)
        rec_decrease_tree(tree)
    return tree


def find_function(content, func_trees, rootname, origin_node, label_num, if_label):
    args_list = []
    count = 0
    for body in content:
        if body.get('type') == 'FunctionDef':
            key = body.get('name')
            lineno = body.get('lineno')
            functionID = gennerate_uuid(rootname, lineno)
            newnode = origin_node[:]
            newnode.append(lineno)
            count = count + 1
            label = label_num[:]
            label.append(str(count))
            get_func_arglist(body, func_trees, newnode)
            setInDict(func_trees, newnode, {'key': functionID, 'name': key, 'label': '.'.join(label)})
            find_function(body.get('body'), func_trees, rootname, newnode, label, if_label)

        elif body.get('type') == 'Expr' and body.get('value').get('type') == 'Call':
            call_lineno = body.get('lineno')
            #todo os.system() to handle
            call_name = (body.get('value').get('func').get('id') == None and body.get('value').get('func').get('value').get('id') or body.get('value').get('func').get('id'))
            Expr_node = origin_node[:]
            Expr_node.append('call')
            setInDict(func_trees, Expr_node, {call_lineno: {'name': call_name}})

        elif body.get('type') == 'Assign' and body.get('value').get('type') == 'Call':
            assign_lineno = body.get('lineno')
            call_assgin = body.get('value').get('func').get('id')
            Assgin_node = origin_node[:]
            Assgin_node.append('call')
            setInDict(func_trees, Assgin_node, {assign_lineno: {'name': call_assgin}})

        elif body.get('type') == 'If':
            if_count = 0
            for body_ in body.get('body'):
                if body_.get('type') == 'FunctionDef':
                    count = count + 1
                    if_node = origin_node[:]
                    if_lineno = body_.get('lineno')
                    funcID = gennerate_uuid(rootname, if_lineno)
                    if_node.append('if')
                    if_func_name = body_.get('name')
                    if_count += 1
                    if_label_num = if_label[:]
                    if_label_num.append(str(if_count))
                    setInDict(func_trees, if_node, {if_lineno: {'name': if_func_name, 'key': funcID, 'label': '.'.join(if_label_num)}})
                    find_function(body.get('body'), func_trees, rootname, if_node, label, if_label_num)


def new_dict(content, new_func_tree, label):
    count = 0
    for body in content:
        if body.get('type') == 'FunctionDef':
            #get_func_id(body,)
            func_name = body.get('name')
            lineno = body.get('lineno')
            count += 1
            re_count = count
            re_label = label[:]
            re_label.append(str(count))
            key = '.'.join(re_label)
            key_parent = '.'.join(re_label[:-1])
            arg_list = get_func_args(body)
            new_func_tree.setdefault(key, {'lineno': lineno, 'name': func_name, 'args': arg_list, 'children': 0})
            if not key_parent:
                if '0' in new_func_tree.keys():
                    add_child = new_func_tree['0'].get('children') + 1
                    new_func_tree['0'].update({'children': add_child})
                else:
                    new_func_tree.setdefault('0', {'children': 1})
            else:
                update_child = new_func_tree[key_parent].get('children') + 1
                new_func_tree[key_parent].update({'children': update_child})
            new_dict(body.get('body'), new_func_tree, re_label)

        elif body.get('type') == 'Expr' and body.get('value').get('type') == 'Call':
            #todo fix the bug of call
            call_lineno = body.get('lineno')
            call_name = (body.get('value').get('func').get('id') == None and body.get('value').get('func').get('value').get('id') or body.get('value').get('func').get('id'))
            expr_label = label[:]
            expr_key = '.'.join(expr_label)
            new_func_tree[expr_key].setdefault('call', {})
            new_func_tree[expr_key]['call'].update({call_lineno: {'name': call_name}})

        elif body.get('type') == 'Assign' and body.get('value').get('type') == 'Call':
            assign_lineno = body.get('lineno')
            assgin_name = body.get('value').get('func').get('id')
            assign_label = label[:]
            assign_key = '.'.join(assign_label)
            new_func_tree[assign_key].setdefault('call', {})
            new_func_tree[assign_key]['call'].update({assign_lineno: {'name': assgin_name}})

        elif body.get('type') == 'If':
            #todo handle the if
            if_label = re_label[:]
            #if_label.append(str(int(if_label[-1])+1))
            #new_func_tree.setdefault('if', {})
         #   print if_label
            new_dict(body.get('body'), new_func_tree, if_label)


def get_func_arglist(func, func_trees, node):
    arg_list = []
    func_args = func.get('args').get('args')
    if func_args is not None:
        if len(func_args) == 1:
            for arg in func_args:
                arg_list = [arg.get('id')]
                setInDict(func_trees, node, {'args': arg_list})
        if len(func_args) > 1:
            for arg in func_args:
                arg_list.append(arg.get('id'))
            setInDict(func_trees, node, {'args': arg_list})


def get_func_args(func):
    arg_list = []
    func_args = func.get('args').get('args')
    if func_args is not None:
        if len(func_args) == 1:
            for arg in func_args:
                arg_list = [arg.get('id')]
            return arg_list
        if len(func_args) > 1:
            for arg in func_args:
                arg_list.append(arg.get('id'))
            return arg_list


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
    dataDict[mapList[-1]].update(value)


def find_function_call(content, detail_func, root_name):
    for body in content:
        if body.get('type') == 'Expr' and body.get('value').get('type') == 'Call':
            call_lineno = body.get('lineno')
            call_name = (body.get('value').get('func').get('id') == None and body.get('value').get('func').get('value').get('id') or body.get('value').get('func').get('id'))
            call_funcID = gennerate_uuid(root_name, call_lineno)

        if body.get('type') == 'FunctionDef':
            func_name = body.get('name')
            lineno = body.get('lineno')
            funcID = gennerate_uuid(root_name, lineno)
            detail_func.setdefault(funcID, {'name': func_name, 'call': lineno})
            find_function_call(body.get('body'), detail_func, root_name)

        if body.get('type') == 'If':
            for body_ in body.get('body'):
                if body_.get('type') == 'FunctionDef':
                    if_func_name = body_.get('name')
                    lineno_ = body_.get('lineno')
                    funcID_ = gennerate_uuid(root_name, lineno_)
                    detail_func.setdefault(funcID_, {'name': if_func_name, 'call': lineno_})


def get_call_funcname(func):
    pass


def print_find_function(content):
    for body in content:
        if body.get('type') == 'FunctionDef':
            key = body.get('name')
            logger.warning('%s', key)
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
    new_func_tree = OrderedDict({})
    detail_func = OrderedDict({})
    find_function(body, func_tree, root_name, [root_name], [], [])
    new_dict(body, new_func_tree, [])
    pp.pprint(dicts(new_func_tree))
    find_function_call(body, detail_func, root_name)
    #pp.pprint(dicts(func_tree))
    #pp.pprint(dicts(detail_func))


if __name__ == "__main__":
    main()


# tpye : ClassDef, FunctionDef, Assign, If, Import, Attribute, Return