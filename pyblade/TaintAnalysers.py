# !env python
# coding=utf-8
#
#
#      TaintAnalyser.py
#
#      Copyright (C) 2014 - 2015 https://github.com/shengqi158/pyvulhunter is origin
#
#                   2015 - 2016 revised by Yong Huang <huangyong@iscas.ac.cn>
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

import json
import logging
import os
from utils import color_log
from utils import dump_python

from collections import OrderedDict

from conf.sources import SOURCE_LIST
from conf.sinks import *

DEBUG = True
ALERT = True

FILE_UNSAFE_FUNCS = set()
CMD_COUNT = 0

is_arg_in = False
is_arg_return_op = False

File = 'taintanalysis.py'

logger = color_log.init_log(logging.DEBUG)
# DEBUG INFO WARNING ERROR CRITICAL

class TaintAnalyzer(object):
    """judge the injection base on ast"""
    def __init__(self, filename, lines):
        try:
            self.tree = dump_python.parse_json_text(filename, lines)
        except Exception, e:
            self.tree = "{}"
            print e
        self.tree = json.loads(self.tree)
        rec_decrease_tree(self.tree)
        dir = os.path.abspath('.')
        files = os.path.join(dir, 'tests\\' + File)
        if DEBUG:
            try:
                fd = open(files+".json", 'w')
                json.dump(self.tree, fd)
                fd.flush()
                fd.close()
            except:
                pass
        self.filename = self.tree.get("filename")
        self.body = self.tree.get("body")
        self.func = {}
        self.funcs = {}
        self.func_lines = {}
        self.taint_top = []
        self.taint_func_top = []
        self.unsafe_func = set()
        self.untreated_func = set()
        self.record_unsafe_func = OrderedDict({})
        self.record_other_unsafe_func = OrderedDict({})
        self.record_param = {}
        self.arg = {}
        self.taint_var = set()
        self.taint_func = set()

    def get_func_objects(self, body, class_name=None):
        """get function structure """
        for obj in body:
            if obj.get('type') == 'FunctionDef':
                if class_name:
                    key = obj.get('name')+":" + class_name
                else:
                    key = obj.get('name')+":"
                self.get_func_objects(obj.get('body'), obj.get('name'))
                self.func.setdefault(key, obj)
            elif obj.get('type') == 'ClassDef':
                self.get_func_objects(obj.get('body'), obj.get('name'))
        return

    def get_func_lines(self, func, func_name):
        """ get the line of the function"""
        #logger.warning('%r,%r', func, func_name)
        if isinstance(func, dict) and 'body' in func:
            lines = func.get('body')
        elif isinstance(func, list):
            lines = func
        elif isinstance(func, dict) and func.get('type') == 'Call':
            lines = [func]
        else:
            lines = []
        for line in lines:
            ast_body = line.get('body')
            ast_orelse = line.get('orelse')
            ast_handlers = line.get('handlers')
            ast_test = line.get('test')
            ast_args = line.get('args')
            if 'value' in line and line.get('value') and 'func' in line.get('value'):
                self.func_lines[func_name].append(line)
                continue
            elif line.get('type') == 'Call':
                self.func_lines[func_name].append(line)
                continue

            if ast_body:
                self.get_func_lines(ast_body, func_name)
            if ast_orelse:
                self.get_func_lines(ast_orelse, func_name)
            if ast_handlers:
                self.get_func_lines(ast_handlers, func_name)
            if ast_test and ast_test.get('type') == 'Compare':
                if ast_test.get('comparators'):
                    self.get_func_lines(ast_test.get('comparators'), func_name)
                if ast_test.get('left'):
                    self.get_func_lines(ast_test.get('left'), func_name)
            if ast_test and ast_test.get('type') == 'BoolOp':
                for value in ast_test.get('values'):
                    if value.get('comparators'):
                        self.get_func_lines(value.get('comparators'), func_name)
                    if value.get('left'):
                        self.get_func_lines(value.get('left'), func_name)

            if ast_args:
                self.get_func_lines(ast_args, func_name)
        return

    def parse_func(self, func, class_name, analyse_all):
        global leafs
        global args_ori
        global is_arg_in
        global CMD_COUNT
        global is_arg_return_op
        is_arg_return_op = False
        arg_leafs = []
        func_name = func.get('name')
        #logger.debug("fucntion_name:%s" %(func_name))
        args_ori = set([arg.get('id') for arg in func.get('args').get("args")]) #arg.id
        if class_name and self.arg.get(class_name):
            arg_tmp = set(self.arg.get(class_name))
            args_ori = args_ori | arg_tmp
        #logger.debug("args:%s" % str(args_ori))
        self.func_lines.setdefault(func_name, [])
        self.get_func_lines(func, func_name)
        lines = self.func_lines[func_name]
        #logger.debug("func_lines:%r" % (lines))
        look_up_arg(func, args_ori, arg_leafs, func_name)
        if func_name == '__init__':
            self.arg.setdefault(class_name, args_ori)
        self.record_param[func_name] = args_ori # ??????
        #print 'func,record_param,i:', func_name,self.record_param.get(func_name),i
        lines = self.func_lines[func_name]
        for line in lines:
            arg_leafs = []
            is_arg_in = False
            value = line.get('value')
            lineno = line.get('lineno')
            if (value and value.get('type') == 'Call') or (line and line.get('type') == 'Call'):
                #logger.debug("value:%r" %(value))
                #line_func = value.get("func") if value else line.get('func')
                line_func = value if value and value.get('type') == 'Call' else line
                #value_args = value.get('args') if value else line.get('args')
                value = value if value else line
                func_ids = []
                rec_get_func_ids(line_func, func_ids)
                func_ids = set(func_ids)
                find_args(value, arg_leafs)

                if func_ids and (func_ids & (set(SOURCE))) and arg_leafs:
                    if set(arg_leafs) & set(self.record_param.get(func_name)):
                        if not is_arg_return_op and func_name not in ('__init__'):
                            FILE_UNSAFE_FUNCS.add(func_name)
                            self.record_unsafe_func.setdefault(lineno, {'func_name': func_name, 'args': args_ori, 'func_ids': func_ids, 'arg_leafs': arg_leafs})
                            CMD_COUNT = CMD_COUNT + 1

    def parse_py(self):
        self.get_func_objects(self.body)

        for key, func in self.func.iteritems():
            self.parse_func(func, key.split(':')[1], True)

    def record_all_func(self):
        from copy import deepcopy
        record = {}
        tmp_record_unsafe_func = deepcopy(self.record_unsafe_func)
        for key, value in tmp_record_unsafe_func.iteritems():
            for func_id in value.get('func_ids'):
                for func in tmp_record_unsafe_func.values():
                    if func_id in func.get('func_name'):
                        record.setdefault(key, [value.get('func_name'), func_id, str(func.get('func_ids'))])

        for key, value in record.iteritems():
            logger.error("File:%s,line:%s,function:%s" %(self.filename, key, '--->'.join(value)))

        if not ALERT:
            for key, value in self.record_unsafe_func.iteritems():
                logger.error("maybe injected File:%s,    line:%s,    function:%s ---> %s" %(self.filename, key, value.get('func_name'), value.get('func_ids')))

                if 'request' in value.get('arg_leafs'):
                    logger.critical("maybe injected File:%s,line:%s,function:%s--->%r" %(self.filename, key, value.get('func_name'), value.get('func_ids')))

    def record_taint_source(self):
        ''' tiant source marked '''
        valset = []
        if 'sys.argv' in SOURCE_LIST:
            for obj in self.body:
                if obj.get('type') == 'If':
                    value = obj.get('body')
                    for val in value:
                        if val.get('type') == 'Assign':
                            ops = val.get('value')
                            target = val.get('targets')
                            for ids in target:
                                self.taint_var = ids.get('id')
                                self.taint_top = [ids.get('id')]
                            try:
                                if isinstance(ops, dict) and ops.get('left').get('value').get('attr') == 'argv' \
                                        and ops.get('left').get('value').get('value').get('id') == 'sys':
                                    lineno = ops.get('left').get('value').get('lineno')
                                    print "locate at lineno:%d  the taint source :  %s "%(lineno, self.lines[lineno - 1])
                            except Exception, e:
                                pass
                            try:
                                if isinstance(ops, dict) and ops.get('right').get('value').get('attr') == 'argv' \
                                        and ops.get('right').get('value').get('value').get('id') == 'sys':
                                    lineno = ops.get('right').get('value').get('lineno')
                                    print "locate at lineno:%d  the taint source :  %s "%(lineno, self.lines[lineno - 1])
                            except Exception, e:
                                pass

    def find_function_def(self, body):
        for obj in body:
            if obj.get('type') == 'FunctionDef':
                key = obj.get('name') + ":"
                self.find_function_def(obj.get('body'))
                self.funcs.setdefault(key, obj)
                print key, obj

    def store_sensitive_route(self):
        '''to record the taint route'''
        for expr in self.body:
            if expr.get('type') == 'If':
                for str in expr.get('body'):
                    if str.get('type') == 'Expr' and str.get('value').get('type') == 'Call':
                        for args in str.get('value').get('args'):
                            if args.get('id') == self.taint_var:
                                self.taint_func = str.get('value').get('func').get('id')
                                self.taint_func_top = [self.taint_func]    #store catfile

    def find_taint_func(self):
        global ALERT
        for func in self.body:
            if func.get('type') == 'FunctionDef' and func.get('name') == self.taint_func:
                var = get_function_args(func)
                self.taint_top.append(var)
                taint_dests = get_assign_target(func, var)
                self.taint_top.append(taint_dests)
                for body in func.get('body'):
                    if body.get('type') == 'Expr' and body.get('value').get('type') == 'Call':
                        self.taint_func_top.append(body.get('value').get('func').get('id'))
                        for dest in body.get('value').get('args'):
                            if self.taint_top[-1] == dest.get('id'):     # cmd = "cat " + filename  -> lineno:21 list_file(cmd)
                                for funcs in self.body:
                                    if funcs.get('type') == 'FunctionDef' and funcs.get('name') == self.taint_func_top[-1]:
                                        vars = get_function_args(funcs)
                                        self.taint_top.append(vars)     #list_file(filename)
                                        target = get_assign_target(funcs, vars)
                                        self.taint_top.append(target)
                                        inner_func = check_inner_function(funcs)
                                        for keys, values in inner_func.iteritems():
                                            self.taint_func_top.append(keys)  # demo(filename) inner
                                        new_taint = get_expr_id(funcs, self.taint_func_top[-1], self.taint_top[-1], inner_func, keys)
                                        self.taint_top.append(new_taint)
                                        print self.taint_func_top

                                        assigned = get_func_body(self.tree, self.taint_func_top[1], self.taint_top[-1])
                                        self.taint_top.append(assigned)
                                        print self.taint_top
                                        for key, value in self.record_unsafe_func.iteritems():
                                            if value.get('arg_leafs') == [self.taint_top[-1]]:
                                                ALERT = False
                                            else:
                                                ALERT = True
        return ALERT

    def source_to_sink(self):
        '''source ->path -> sink'''
        self.record_taint_source()
        self.store_sensitive_route()
        ret = self.find_taint_func()
        return ret


def get_expr_id(funcs, taint_func, taint_var, inner_func, key):
    for funcs_ in funcs.get('body'):
        if funcs_.get('type') == 'Expr' and funcs_.get('value').get('type') == 'Call':
            for args in funcs_.get('value').get('args'):
                if args.get('id') == taint_var:
                    if funcs_.get('value').get('func').get('id') == taint_func:
                        value = inner_func.get(key)
    return value


def get_func_body(func, taint_func, taint_var):
    for body in func.get('body'):
        if body.get('type') == 'FunctionDef' and body.get('name') == taint_func:
            for bodys in body.get('body'):
                if bodys.get('type') == 'FunctionDef':
                    for indexs in bodys.get('body'):
                        if indexs.get('type') == 'Assign':
                            ops = indexs.get('value')
                            if 'right' in ops:
                                if ops.get('right').get('id') == taint_var:
                                    for ids in indexs.get('targets'):
                                        return ids.get('id')


def get_assign_target(func, taint):
    target_ = 'none'
    for body in func.get('body'):
        if body.get('type') == 'Assign':
            ops = body.get('value')
            if 'right' in ops:
                ops_ = ops.get('right')
                if ops_.get('id') == taint:
                    for ids in body.get('targets'):
                        target_ = ids.get('id')
    return target_


def check_inner_function(func):
    funcs = {}
    for fun in func.get('body'):
        if fun.get('type') == 'FunctionDef':
            func_name = fun.get('name')
            var = get_function_args(fun)
        else:
            pass
    funcs.setdefault(func_name, var)
    return funcs


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


def rec_get_func_ids(func, func_ids):
    if func.get('type') in ('Name', 'Attribute'):
        get_func_id(func, func_ids)
    if 'value' in func and func.get('value').get('func'):
        rec_get_func_ids(func.get('value').get('func'), func_ids)
    if func.get('type') == 'Call':
        rec_get_func_ids(func.get('func'), func_ids)
        for args in func.get('args'):
            if args.get('type') != 'Name':
                rec_get_func_ids(args, func_ids)
    return


def rec_get_targets(targets, out_targets):
    """recursive to find the target"""
    for target in targets:
        if target.get('type') == 'Subscript':
            rec_get_targets([target.get('value')], out_targets)
        elif target.get('type') == 'Name':
            out_targets.append(target.get('id'))
        elif target.get('type') == 'Attribute':
            if target.get('value').get('type') == 'Name' and target.get('value').get('id') == 'self':
                out_targets.append('self.'+target.get('attr'))
    return


def get_func_id(func, func_ids):
    """get function name """
    if func.get('type') == 'Name':
        func_id = func.get('id')
    elif func.get('type') == 'Attribute':
        if func.get('value').get('type') == 'Name':
            module = func.get('value').get('id')
            if module in ['os', 'pickle']:
                func_id = module + "." + func.get('attr')
            else:
                func_id = func.get('attr')
        elif func.get('value').get('type') == 'Attribute':
            func_id = func.get('attr')
        elif func.get('value').get('type') == 'Subscript':
            func_id = func.get('attr')
        else:
            func_id = None
    else:
        func_id = None
    if func_id:
        func_ids.append(func_id)


def get_function_args(func):
    for args in func.get('args').get('args'):
        var = args.get('id')
    return var


def find_args(operand, args):
    #logger.warning('%r, %r', operand, args)
    if isinstance(operand, list) or isinstance(operand, tuple):
        find_all_leafs(operand, args)
    elif isinstance(operand, dict):
        if operand.get('type') == 'Call':
            if 'args' in operand:
                find_all_leafs(operand.get('args'), args)
            if 'value' in operand.get('func'):
                find_args(operand.get('func').get('value'), args)
        elif operand.get('type') == 'UnaryOp':
            find_args(operand.get('operand'), args)
        elif operand.get('type') == 'BinOp':
            find_arg_leafs(operand, args)
    else:
        return


def find_all_leafs(args, leafs):
    for arg in args:
        find_arg_leafs(arg, leafs)


def find_arg_leafs(arg, leafs):
    """recursive to find all leafs"""
    fields = arg.get('_fields')
    #logger.warn('entry into find_arg_leafs: %r, %r', arg, leafs)
    _type = arg.get('type')
    if _type == 'Attribute':
        parent, topids = {}, []
        rec_get_attr_top_id(arg, parent, topids)
        #logger.warning("parent:%r,topids:%r" %(parent, topids))
        if topids and 'self' in topids[0].lower():
            leafs.append(topids[0])
        elif topids and topids[0].lower() != 'request' and topids[0].lower() != 'self':
            leafs.append(topids[0])
            #logger.warn("1parent:%r,topids:%r" %(parent, topids))
        elif topids and parent and parent.get('type') == 'Attribute' and parent.get('attr') in REQUEST_VAR:
            leafs.append(topids[0])
            #logger.warn("2parent:%r,topids:%r" %(parent, topids))
        #find_arg_leafs(arg.get('value'), leafs)
    if _type == 'Name':
        leafs.append(arg.get('id'))
    if _type == 'Call':
        func_ids = []
        rec_get_func_ids(arg.get('func'), func_ids)
        logger.info('func_ids:%r,funcs:%r' % (func_ids, set(SOURCE)))
        if set(func_ids) & (set(SOURCE) | set(FILE_UNSAFE_FUNCS)):
            for value in arg.get('args'):
                parent, topids = {}, []
                rec_get_attr_top_id(value, parent, topids)
                logger.warn("parent:%r,topids:%r" %(parent, topids))
                logger.warn("value:%r," %(value))
                if topids and 'self' in topids[0].lower() :
                    leafs.append(topids[0])
                elif topids and topids[0].lower() != 'request' and topids[0].lower() != 'self':
                    leafs.append(topids[0])
                    logger.warn("1parent:%r,topids:%r" %(parent, topids))
                elif topids and parent and parent.get('type')=='Attribute' and parent.get('attr') in REQUEST_VAR:
                    leafs.append(topids[0])
                    logger.warn("2parent:%r,topids:%r" %(parent, topids))

            for arg_item in arg.get('args'):
                find_arg_leafs(arg_item, leafs)
        if arg.get('func') and arg.get('func').get('type') != 'Name':
            find_arg_leafs(arg.get('func'), leafs)
    if _type == 'Subscript':
        find_arg_leafs(arg.get('value'), leafs)
    if _type == 'BinOp' and fields:
        if 'right' in fields:
            if arg.get('right').get('type') == 'Name':
                right_id = arg.get("right").get("id")
                if right_id:
                    leafs.append(right_id)
            elif arg.get('right').get('type') == 'Tuple':
                for elt in arg.get('right').get('elts'):
                    find_arg_leafs(elt, leafs)
            elif arg.get('right').get('type') == 'Call':
                find_arg_leafs(arg.get('right'), leafs)

        if 'left' in fields and not arg.get('left').get('_fields'):
            left_id = arg.get('left').get('id')
            if left_id:
                leafs.append(left_id)
        if 'left' in fields and arg.get('left').get('_fields'):
            find_arg_leafs(arg.get('left'), leafs)
    return


def rec_get_attr_top_id(func, parent, ids):
    """
    ids： return the result
    """
    if func.get('type') == 'Name':
        print func.get('type')
        ids.append(func.get('id'))
    if func.get('type') == 'Attribute':
        parent.update(func)
        if func.get('value').get('type') == 'Name' and func.get('value').get('id') == 'self':
            ids.append('self.'+func.get('attr'))
            return
        else:
            rec_get_attr_top_id(func.get('value'), parent, ids)
    if func.get('type') == 'Call':
        parent.update(func)
        rec_get_attr_top_id(func.get('func'), parent, ids)
    if func.get('type') == 'Subscript':
        parent.update(func)
        rec_get_attr_top_id(func.get('value'), parent, ids)
    return

def look_up_arg(func, args_ori, args, func_name):
    """ recusive to find unsafe function args
    func: test function,args_ori: test function args，args: unsafe function args
    """
    global is_arg_in
    if isinstance(func, dict) and 'body' in func:
        lines = func.get('body')
    elif isinstance(func, list):
        lines = func
    elif isinstance(func, dict) and func.get('type') == 'Call':
        lines = [func]
    else:
        lines = []

    for line in lines:
        #        print 'look_up_arg:line:',line
        ast_body = line.get('body')
        ast_orelse = line.get('orelse')
        ast_handlers = line.get('handlers')
        ast_test = line.get('test')
        ast_args = line.get('args')
        # 处理单纯属性
        if line.get('type') == 'Assign':
            target_ids = []
            rec_get_targets(line.get('targets'), target_ids)
        else:
            target_ids = []

        if line.get("type") == "Assign" and "value" in line and line.get("value").get("type") == "Name":
            if target_ids and line.get("value").get("id") in args_ori:
                args_ori.update(target_ids)
                logger.info("In Assign,Name add (%r) to (%r) where line=(%r) line=(%r)" % (
                target_ids, args_ori, line.get('lineno'), line))

        if line.get("type") == "Assign" and "value" in line and line.get("value").get("type") == "Attribute":
            value_func = line.get('value').get('value')
            if value_func and value_func.get("type") == 'Name':
                if target_ids and value_func.get("id") in args_ori:
                    args_ori.update(target_ids)
                    logger.info("In Assign,Attr add (%r) to (%r) where line=(%r) line=(%r)" % (
                    target_ids, args_ori, line.get('lineno'), line))

            else:
                topids = []
                parent = {}
                rec_get_attr_top_id(value_func, parent, topids)
                if (set(topids) & set(args_ori)):
                    if topids and topids[0].lower() == 'request':
                        if parent and parent.get('type') == 'Attribute' and parent.get('attr') in REQUEST_VAR:
                            args_ori.update(target_ids)
                            logger.info("In Assign,Attr add (%r) to (%r) where line=(%r) line=(%r)" % (
                            target_ids, args_ori, line.get('lineno'), line))
                        elif parent and parent.get('type') == 'Attribute':
                            args_ori.difference_update(set(target_ids))
                            logger.warn(
                                "In Assign,Attr delete (%r) from (%r) where line=(%r)***************************** line=(%r)" % (
                                target_ids, args_ori, line.get('lineno'), line))

        # 处理字符串拼接过程
        if line.get("type") == "Assign" and "value" in line and line.get("value").get("type") == "BinOp":
            #            right = line.get('value').get('right')
            #            if right.get('type') == 'Tuple':
            #                rec_find_args(right.get('elts'))
            leafs = []
            find_arg_leafs(line.get("value"), leafs)
            #logger.info('----%r----%r' % (args_ori, leafs))
            if (set(args_ori) & set(leafs)):
                if target_ids:
                    args_ori.update(target_ids)
                    #logger.info("In Assign,BinOp add (%r) to (%r) where line=(%r)" % (target_ids, args_ori, line.get('lineno')))
        # 列表解析式
        if line.get("type") == "Assign" and "value" in line and line.get("value").get("type") in (
        "ListComp", "SetComp"):
            generators = line.get('value').get('generators')
            leafs = []
            for generator in generators:
                find_arg_leafs(generator.get('iter'), leafs)
                if target_ids and (set(args_ori) & set(leafs)):
                    args_ori.update(target_ids)
                    logger.info("In Assign,ListComp,SetComp add (%r) to (%r) where line=(%r) line=(%r)" % (
                    target_ids, args_ori, line.get('lineno'), line))

        # 处理列表中相加
        if line.get('type') == 'Assign' and 'value' in line and line.get('value').get('type') in ('List', 'Tuple'):
            leafs = []
            for elt in line.get('value').get('elts'):
                find_arg_leafs(elt, leafs)
                if (set(args_ori) & set(leafs)):
                    if target_ids:
                        args_ori.update(target_ids)
                        logger.info("In Assign,List add (%r) to (%r) where line=(%r) line=(%r)" % (
                        target_ids, args_ori, line.get('lineno'), line))

        # 处理 tmp= {'bb':a}情况
        if line.get('type') == 'Assign' and 'value' in line and line.get('value').get('type') in ('Dict'):
            leafs = []
            for value in line.get('value').get('values'):
                find_arg_leafs(value, leafs)
                if (set(args_ori) & set(leafs)):
                    if target_ids:
                        args_ori.update(target_ids)
                        logger.info("In Assign,Dict add (%r) to (%r) where line=(%r) line=(%r)" % (
                        target_ids, args_ori, line.get('lineno'), line))

        # 处理Subscript分片符情况
        if line.get('type') == 'Assign' and 'value' in line and line.get('value').get('type') == 'Subscript':
            value_type = line.get('value').get('value').get('type')
            value_func_ids = []
            rec_get_func_ids(line.get('value').get('value'), value_func_ids)
            value_func_ids = set(value_func_ids)
            value_arg_ids = []
            find_arg_leafs(line.get('value').get('value'), value_arg_ids)
            if value_type == 'Attribute':
                if value_func_ids and value_func_ids.issubset((set(REQUEST_VAR) | set(STR_FUNCS))):
                    if target_ids and not (set(value_arg_ids) & set(target_ids)):
                        args_ori.update(target_ids)
                        logger.info("In Assign,Subscript add (%r) to (%r) where line=(%r) line=(%r)" % (
                        target_ids, args_ori, line.get('lineno'), line))

        # 处理调用函数后的赋值,像str，get取值都保留
        if line.get("type") == "Assign" and "value" in line and line.get("value").get("type") == "Call":
            value_arg_ids = []
            rec_find_args(line.get('value'), value_arg_ids)
            value_func_ids = []
            rec_get_func_ids(line.get('value').get('func'), value_func_ids)
            value_func_ids = set(value_func_ids)
            value_func_type = line.get("value").get('func').get('type')
            value_func = line.get('value').get('func')
            (topids, parent) = ([], {})
            rec_get_attr_top_id(value_func, parent, topids)
            logger.info('In Call:topids:%r,value_arg_ids:%r,value_func_ids:%r,line:%r' % (topids, value_arg_ids, value_func_ids, line))

            if value_arg_ids or topids:
                # 处理普通方法
                if value_func_type == 'Name' and (set(value_arg_ids) & set(args_ori)):


                    if target_ids :  # 开了verbose模式，函数处理后的则直接加入到变量中
                        args_ori.update(target_ids)
                        logger.info("In Assign,Call:Verbose Name add (%r) to (%r) where line=(%r) line=(%r)" % (target_ids, args_ori, line.get('lineno'), line))
                    else:
                        if target_ids and value_func_ids and value_func_ids.issubset(
                                (set(STR_FUNCS) | set(SOURCE))):
                            args_ori.update(target_ids)
                            logger.info("In Assign,Call:Name add (%r) to (%r) where line=(%r) line=(%r)" % (target_ids, args_ori, line.get('lineno'), line))
                        elif target_ids and value_func_ids and (
                            value_func_ids & ((set(SOURCE) | set(FILE_UNSAFE_FUNCS)))):
                            is_arg_in = True
                        elif target_ids and value_func_ids and set(value_func_ids) & (set(SOURCE)):
                            args_ori.difference_update(target_ids)
                            logger.warn(
                                "In Assign,Call delete (%r) from (%r) where line=(%r)***************************** type=(%r)" % (
                                target_ids, args_ori, line.get('lineno'), line))
                        elif target_ids:
                            args_ori.difference_update(target_ids)
                            logger.warn(
                                "In Assign,Call delete (%r) from (%r) where line=(%r)***************************** type=(%r)" % (
                                target_ids, args_ori, line.get('lineno'), line))
                            #                            for target in target_ids:#处理cmd=int(cmd) 这种情况
                            #                                args_ori.difference_update(target_ids)
                            #                                if target in args_ori:
                            #                                    args_ori.discard(target)
                            #                                    logger.info("arg_id,assign31:%r,args_ori:%r" %(value_arg_ids, args_ori))

                elif value_func_type == 'Attribute':  # 处理属性方法，如从dict取值

                    if (set(topids) & set(args_ori)):
                        if topids[0].lower() == 'request':
                            if parent and parent.get('type') == 'Attribute' and parent.get('attr') in REQUEST_VAR:
                                if target_ids and not (set(value_arg_ids) & set(target_ids)):
                                    args_ori.update(target_ids)
                                    logger.info("In Assign,Call:attr add (%r) to (%r) where line=(%r) type=(%r)" % (
                                    target_ids, args_ori, parent.get('lineno'), line))
                            elif parent and parent.get('type') == 'Attribute':
                                args_ori.difference_update(set(target_ids))  # 去除target_ids
                                logger.warn(
                                    "In Assign,Call:attr delete (%r) from (%r) where line=(%r)***************************** type=(%r)" % (
                                    target_ids, args_ori, line.get('lineno'), line))

                        elif value_func_ids and value_func_ids.issubset(set(STR_FUNCS) | set(SOURCE)) and (
                            set(value_arg_ids) & set(args_ori)):
                            if target_ids and not (set(value_arg_ids) & set(target_ids)):
                                args_ori.update(target_ids)
                                logger.info("In Assign,Call:attr add (%r) to (%r) where line=(%r) type=(%r)" % (
                                target_ids, args_ori, line.get('lineno'), line))
                        elif value_func_ids and set(value_func_ids) & set(SAFE_FUNCS) :
                            if target_ids and not (set(value_arg_ids) & set(target_ids)):
                                args_ori.difference_update(target_ids)
                                logger.warn(
                                    "In Assign,Call:attr delete (%r) from (%r) where line=(%r)***************************** type=(%r)" % (
                                    target_ids, args_ori, line.get('lineno'), line))
                        else:
                            if target_ids and not (set(value_arg_ids) & set(target_ids)):
                                args_ori.update(target_ids)
                                logger.info("In Assign,Call:attr add (%r) to (%r) where line=(%r) type=(%r)" % (
                                target_ids, args_ori, line.get('lineno'), line))
                    # 处理r=unicode(s).encode('utf8')
                    elif value_func_ids and value_func_ids.issubset(set(STR_FUNCS) | set(SOURCE)) and (
                        set(value_arg_ids) & set(args_ori)):
                        if target_ids and not (set(value_arg_ids) & set(target_ids)):
                            args_ori.update(target_ids)
                            logger.info("In Assign,Call:attr add (%r) to (%r) where line=(%r) type=(%r)" % (
                            target_ids, args_ori, line.get('lineno'), line))

                    elif value_func_ids and value_func_ids.issubset(set(STR_FUNCS) | set(SOURCE)) and (
                        set(topids) & set(args_ori)):
                        if target_ids and not (set(value_arg_ids) & set(target_ids)):
                            args_ori.update(target_ids)
                            logger.info("In Assign,Call:attr add (%r) to (%r) where line=(%r) type=(%r)" % (
                            target_ids, args_ori, line.get('lineno'), line))
                    elif value_func_ids and set(value_func_ids) & set(SAFE_FUNCS):
                        if target_ids:
                            args_ori.difference_update(target_ids)
                            logger.warn(
                                "In Assign,Call:attr delete (%r) from (%r) where line=(%r)***************************** type=(%r)" % (
                                target_ids, args_ori, line.get('lineno'), line))




                    elif value_func_ids and (value_func_ids & (set(SOURCE) | set(FILE_UNSAFE_FUNCS))):  # 处理危险函数
                        leafs = []
                        leafs = value_arg_ids
                        if set(leafs) & set(args_ori):
                            is_arg_in = True

        if line.get('type') == 'Return' and 'value' in line and line.get('value'):
            value_id = line.get('value').get('id')
            if value_id and value_id in args_ori:
                print 'untrited_func_name', func_name
                SOURCE.add(func_name)

        if line.get('type') == 'For':
            iter_args = []
            find_arg_leafs(line.get('iter'), iter_args)
            if set(iter_args) & set(args_ori):
                targets = []
                find_arg_leafs(line.get('target'), targets)
                if targets:
                    args_ori.update(targets)
                    logger.info("In For Call add (%r) to (%r) where line=(%r) line=(%r)" % (
                    target_ids, args_ori, line.get('lineno'), line))

        if line.get("type") == "Expr" and "value" in line and line.get("value").get("type") == "Call":
            value_arg_ids = []
            rec_find_args(line.get('value'), value_arg_ids)
            if set(value_arg_ids) & set(args_ori):
                is_arg_in = True

        if line.get('type') == 'Call':  # 处理if语句中中eval类似函数
            func_ids = []
            rec_get_func_ids(line.get('func'), func_ids)
            args_tmp = []
            rec_find_args(line, args_tmp)
            if (set(args_tmp) & args_ori) and func_ids and (
                set(func_ids) & (set(SOURCE) | set(FILE_UNSAFE_FUNCS))):
                is_arg_in = True
                logger.info('type:call')
                #        if line.get('type') == 'Ififif':
        if line.get('type') == 'If':
            is_if_return = False
            is_if_param = False
            is_in_param = False

            if_judge_func = set(['exists', 'isfile', 'isdir', 'isabs', 'isdigit'])
            for body in line.get('body'):
                if body.get('type') == 'Return':
                    is_if_return = True
            test = line.get('test')
            if test and test.get('type') == 'UnaryOp':
                operand = test.get('operand')
                args_tmp = []
                if operand:
                    rec_find_args(operand, args_tmp)
                    if set(args_tmp) & set(args_ori):
                        is_if_param = True
                func_ids = []
                rec_get_func_ids(operand, func_ids)
                if set(func_ids) & if_judge_func and is_if_return and is_if_param:
                    args_ori.difference_update(args_tmp)
                    logger.warn("In If delete (%r) from (%r) where line=(%r)***************************** type=(%r)" % (
                    args_tmp, args_ori, test.get('lineno'), test.get('type')))

            if test and test.get('type') == 'Compare':
                args_tmp = []
                for key, value in test.iteritems():
                    if key == 'left':
                        if test[key].get('type') == 'Name':
                            args_tmp = [test[key].get('id')]
                    if key == 'comparators':
                        for comparator in test[key]:
                            if comparator.get('type') in ('List', 'Tuple'):
                                for elt in comparator.get('elts'):
                                    if elt.get('type') == 'Name' and elt.get('id') in args_ori:
                                        is_in_param = True
                if set(args_tmp) & set(args_ori) and is_if_return and not is_in_param:
                    args_ori.difference_update(args_tmp)
                    logger.warn("In If delete (%r) from (%r) where line=(%r)***************************** type=(%r)" % (
                    args_tmp, args_ori, test.get('lineno'), test.get('type')))

        if ast_body:
            look_up_arg(ast_body, args_ori, args, func_name)
        if ast_orelse:
            look_up_arg(ast_orelse, args_ori, args, func_name)
        if ast_handlers:
            look_up_arg(ast_handlers, args_ori, args, func_name)
        if ast_test and ast_test.get('comparators'):
            look_up_arg(ast_test.get('comparators'), args_ori, args, func_name)
        if ast_test and ast_test.get('left'):
            look_up_arg(ast_test.get('left'), args_ori, args, func_name)
        if ast_args:
            look_up_arg(ast_args, args_ori, args, func_name)

    return


def rec_find_args(operand, args):
    if isinstance(operand, list) or isinstance(operand, tuple):
        find_all_leafs(operand, args)
    elif isinstance(operand, dict):
        if operand.get('type') == 'Call':
            if "args" in operand:
                find_all_leafs(operand.get('args'), args)
            if "value" in operand.get('func'):
                rec_find_args(operand.get('func').get('value'), args)
        elif operand.get('type') == 'UnaryOp':  # not param判断中
            rec_find_args(operand.get('operand'), args)
        elif operand.get('type') == 'BinOp':
            find_arg_leafs(operand, args)

    else:
        return