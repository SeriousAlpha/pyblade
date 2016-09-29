# !env python
# coding=utf-8
#
#
#      marktaint.py
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

from conf.sources import SOURCE_LIST
from conf.sinks import SOURCE
from functiondef import files, strings, get_tree, traverse_tree, new_dict, pp, dicts
from TaintAnalysers import find_arg_leafs, rec_get_targets
from collections import OrderedDict

import logging
import utils
import pprint

logger = utils.color_log.init_log(logging.DEBUG)


def mark_taint_var(strings):
    taint_var = []
    lines = strings.split('\n')
    for line in lines:
        for source in SOURCE_LIST:
            if source in line and '=' in line:
                target = line.split('=')
                for i in range(len(target)):
                    target[i] = target[i].strip()
                taint_var.append(target[0])
    return taint_var


def mark_unsafe_func(strings):
    lines = strings.split('\n')
    for line in lines:
        for source in SOURCE:
            if source in line:
                print source


def handle_strcat(dict_func, taint_func):
    #pp.pprint(dicts(dict_func))
    for key, value in dict_func.iteritems():
        if 'body' in value:
            func = value.get('body')
            args_ori = set([arg.get('id') for arg in func.get('args').get("args")])
            handle_assign(func, args_ori)
        def_name = value.get('name')
        if taint_func == def_name:   # function call match ,cat_file()
            call = value.get('call')
            for lineno, call in call.iteritems():
                call_key = call.get('label')
                call_args = call.get('args')
                if set(call_args) & set(args_ori):
                    print call_args, args_ori
                    print dict_func[str(call_key)]


def parse_func_body(func, unsafe_func):
    # 判断函数体里是否有危险函数，编写遍历函数体的函数
    #todo 抽空写一下这个函数
    pass


def handle_assign(func, args_ori):
    if isinstance(func, dict) and 'body' in func:
        lines = func.get('body')
    elif isinstance(func, list):
        lines = func
    elif isinstance(func, dict) and func.get('type') == 'Call':
        lines = [func]
    else:
        lines = []

    for line in lines:
        if line.get('type') == 'Assign':
            target_ids = []
            rec_get_targets(line.get('targets'), target_ids)
        else:
            target_ids = []

        if line.get("type") == "Assign" and "value" in line and line.get("value").get("type") == "BinOp":
            leafs = []
            find_arg_leafs(line.get("value"), leafs)
            if set(args_ori) & set(leafs):
                if target_ids:
                    args_ori.update(target_ids)
                    #logger.info("In Assign,BinOp add (%r) to (%r) where line=(%r)" % (target_ids, args_ori, line.get('lineno')))
                    return leafs


def get_func(body):
    func_enum = []
    for func in body:
        if func.get('type') == 'FunctionDef':
            func_enum.append(func)
            get_func(func.get('body'))
    return func_enum


def get_main_unsafe(body, taint_var):
    for mains in body:
        if mains.get('type') == 'If':
            lines = mains.get('body')
            for line in lines:
                if line.get('type') == 'Expr' and line.get('value').get('type') == 'Call':
                    args = line.get('value').get('args')
                    for arg in args:
                        if arg.get('type') == 'Name':
                            call_args = arg.get('id')
                            func_name = line.get('value').get('func').get('id')

    if judge_call_arg(call_args, taint_var):
        return func_name
    else:
        return None


def judge_call_arg(call_args, taint_var):
    for var in taint_var:
        if call_args == var:
            return True
        else:
            return False


def main():
    tree = get_tree(files)
    new_func_tree = OrderedDict({})
    body = tree.get('body')
    new_dict(body, new_func_tree, [])
    func = traverse_tree(new_func_tree)
    #pp.pprint(dicts(func))
    taint_var = mark_taint_var(strings)
    taint_func = get_main_unsafe(body, taint_var)
    handle_strcat(func, taint_func)

    mark_unsafe_func(strings)


if __name__ == "__main__":
    main()

