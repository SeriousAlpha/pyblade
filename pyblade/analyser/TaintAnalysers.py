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
from utils import color_log
from utils import dump_python

from collections import OrderedDict

from conf.sources import SOURCE_LIST
from conf.sinks import SOURCE

DEBUG = False
ALERT = True

FILE_UNSAFE_FUNCS = set()
CMD_COUNT = 0

#args_ori = set([])
is_arg_in = False
is_arg_return_op = False
i = 0

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
        if DEBUG:
            try:
                fd = open(filename+".json", 'w')
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
            if obj.get("type") == "FunctionDef":
                if class_name:
                    key = obj.get('name')+":" + class_name
                else:
                    key = obj.get('name')+":"
                self.get_func_objects(obj.get('body'), obj.get('name'))
                self.func.setdefault(key, obj)
                #print self.func
            elif obj.get('type') == 'ClassDef':
                self.get_func_objects(obj.get('body'), obj.get('name'))
        return

    def get_func_lines(self, func, func_name):
        """ get the line of the function"""
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
            if "value" in line and line.get('value') and "func" in line.get("value"):
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
        global i
        i = i + 1
        is_arg_return_op = False
        arg_leafs = []
        func_name = func.get("name")
        args_ori = set([arg.get('id') for arg in func.get('args').get("args")]) #arg.id
        if class_name and self.arg.get(class_name):
            arg_tmp = set(self.arg.get(class_name))
            args_ori = args_ori | arg_tmp
        self.func_lines.setdefault(func_name, [])
        #print i, self.func_lines
        self.get_func_lines(func, func_name)
        #print self.get_func_lines(func, func_name)
        if func_name == '__init__':
            self.arg.setdefault(class_name, args_ori)
        self.record_param[func_name] = args_ori # ??????
        #print 'func,record_param,i:', func_name,self.record_param.get(func_name),i
        lines = self.func_lines[func_name]
        #print lines
        #analysis all function statements
        for line in lines:
            arg_leafs = []
            is_arg_in = False
            value = line.get("value")
            lineno = line.get("lineno")
            if (value and value.get("type") == "Call") or (line and line.get('type') == 'Call'):
                #logger.debug("value:%r" %(value))
                #line_func = value.get("func") if value else line.get('func')
                #print value, line
                line_func = value if value and value.get('type') == 'Call' else line
                #value_args = value.get('args') if value else line.get('args')
                value = value if value else line
                func_ids = []
                rec_get_func_ids(line_func, func_ids)
                func_ids = set(func_ids)
                rec_find_args(value, arg_leafs)

#                if analyse_all:
#                    look_up_arg(func, args_ori, arg_leafs,func_name)
#                print "UNTREATED_FUNS", UNTREATED_FUNS
                if func_ids and (func_ids & (set(SOURCE))) and arg_leafs:
                    if set(arg_leafs) & set(self.record_param.get(func_name)):
                        if not is_arg_return_op and func_name not in ("__init__"):
                            FILE_UNSAFE_FUNCS.add(func_name)
                            self.record_unsafe_func.setdefault(lineno, {'func_name': func_name, 'args': args_ori, 'func_ids': func_ids, 'arg_leafs': arg_leafs})
                            print self.record_unsafe_func
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

        if ALERT:
            for key, value in self.record_unsafe_func.iteritems():
                logger.error("maybe injected File:%s,    line:%s,    function:%s ---> %s" %(self.filename, key, value.get('func_name'), value.get('func_ids')))

                if 'request' in value.get('arg_leafs'):
                    logger.critical("maybe injected File:%s,line:%s,function:%s--->%r" %(self.filename, key, value.get('func_name'), value.get('func_ids')))

    def record_taint_source(self):
        ''' tiant source marked '''
        valset = []
        if 'sys.argv' in SOURCE_LIST:
            for obj in self.body:
                if obj.get("type") == "If":
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
            if obj.get("type") == "FunctionDef":
                key = obj.get('name') + ":"
                #todo: improve the recursion
                self.find_function_def(obj.get('body'))
                self.funcs.setdefault(key, obj)
                print key, obj

    #todo: do handle recursion

    '''def find_args_leafs(self, args):
        for arg in args:
            self.find_args_leafs(arg)
            print arg'''

    def store_sensitive_route(self):
        '''to record the taint route'''
        for expr in self.body:
            if expr.get("type") == "If":
                for str in expr.get("body"):
                    if str.get("type") == "Expr" and str.get("value").get("type") == "Call":
                        for args in str.get("value").get("args"):
                            if args.get("id") == self.taint_var:
                                self.taint_func = str.get("value").get("func").get("id")
                                self.taint_func_top = [self.taint_func]    #store catfile

    def find_taint_func(self):
        global ALERT
        for func in self.body:
            if func.get("type") == "FunctionDef" and func.get("name") == self.taint_func:
                var = get_function_args(func)
                self.taint_top.append(var)
                taint_dests = get_assign_target(func, var)
                self.taint_top.append(taint_dests)
                for body in func.get("body"):
                    if body.get("type") == "Expr" and body.get("value").get("type") == "Call":
                        self.taint_func_top.append(body.get('value').get('func').get('id'))
                        for dest in body.get("value").get("args"):
                            if self.taint_top[-1] == dest.get("id"):     # cmd = "cat " + filename  -> lineno:21 list_file(cmd)
                                for funcs in self.body:
                                    if funcs.get("type") == "FunctionDef" and funcs.get("name") == self.taint_func_top[-1]:
                                        vars = get_function_args(funcs)
                                        self.taint_top.append(vars)     #list_file(filename)
                                        target = get_assign_target(funcs, vars)
                                        self.taint_top.append(target)
                                        inner_func = check_inner_function(funcs)
                                        for keys, values in inner_func.iteritems():
                                            self.taint_func_top.append(keys)  # demo(filename) inner
                                        for funcs_ in funcs.get('body'):

                                            if funcs_.get('type') == 'Expr' and funcs_.get('value').get('type') == 'Call':
                                                for args in funcs_.get('value').get('args'):
                                                    if args.get('id') == self.taint_top[-1]:
                                                        if funcs_.get('value').get('func').get('id') == self.taint_func_top[-1]:
                                                            self.taint_top.append(values)

                                for bodys in self.body:
                                    if bodys.get("type") == "FunctionDef" and bodys.get("name") == self.taint_func_top[1]:
                                        for bodys_ in bodys.get('body'):
                                            if bodys_.get('type') == 'FunctionDef':
                                                for indexs in bodys_.get('body'):
                                                    if indexs.get('type') == 'Assign':
                                                        ops_ = indexs.get('value')
                                                        if 'right' in ops_:
                                                            if ops_.get('right').get('id') == self.taint_top[-1]:
                                                                for id_ in indexs.get('targets'):
                                                                    self.taint_top.append(id_.get('id'))
                                                                    print self.taint_top
                                                                    for key, value in self.record_unsafe_func.iteritems():
                                                                        if value.get('arg_leafs') == [self.taint_top[-1]]:
                                                                            ALERT = False
                                                                        else:
                                                                            ALERT = True

    def source_to_sink(self):
        '''source ->path -> sink'''
        self.record_taint_source()
        self.store_sensitive_route()
        self.find_taint_func()


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
    if func.get('type') in ("Name","Attribute"):
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
    if func.get("type") == "Name":
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

def find_all_leafs(args, leafs):

    for arg in args:
        find_arg_leafs(arg, leafs)

def get_function_args(func):
    for args in func.get('args').get('args'):
        var = args.get('id')
    return var

def get_assign_target(func, taint):
    target_ = 'none'
    for body in func.get('body'):
        if body.get("type") == "Assign":
            ops = body.get('value')
            if "right" in ops:
                ops_ = ops.get("right")
                if ops_.get("id") == taint:
                    for ids in body.get("targets"):
                        target_ = ids.get("id")
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

def find_func_leafs(value, args_ori, target_ids, import_func):
    """handle the situation of function"""
    value_arg_ids = []
    rec_find_args(value, value_arg_ids)
    value_func_ids = []
    rec_get_func_ids(value.get('func'), value_func_ids)
    value_func_ids = set(value_func_ids)
    value_func_type = value.get('func').get('type')
    value_func = value.get('func')
    (topids, parent) = ([], {})
    rec_get_attr_top_id(value_func, parent, topids)

    if value_arg_ids or topids:
        #handle the method
        if value_func_type == 'Name' and (set(value_arg_ids)&args_ori):
            for func_id in set(import_func.keys())&value_func_ids:
                value_func_ids.add(import_func.get(func_id))
                value_func_ids.remove(func_id)

        elif target_ids:
            args_ori.difference_update(target_ids)

def find_arg_leafs(arg, leafs):
    """recursive to find all leafs"""
    fields = arg.get("_fields")
    _type = arg.get('type')
    if _type == "Attribute":
        parent, topids = {}, []
        rec_get_attr_top_id(arg, parent, topids)
        #logger.warning("parent:%r,topids:%r" %(parent, topids))
        if topids and 'self' in topids[0].lower() :
            leafs.append(topids[0])
        elif topids and topids[0].lower() != 'request' and topids[0].lower() != 'self':
            leafs.append(topids[0])
            #logger.warn("1parent:%r,topids:%r" %(parent, topids))
        elif topids and parent and parent.get('type') == 'Attribute' and parent.get('attr') in REQUEST_VAR:
            leafs.append(topids[0])
            #logger.warn("2parent:%r,topids:%r" %(parent, topids))
        #find_arg_leafs(arg.get('value'), leafs)
    if _type == "Name":
        leafs.append(arg.get('id'))
    if _type == 'Call':
        func_ids = []
        rec_get_func_ids(arg.get('func'), func_ids)
        #logger.info('func_ids:%r,funcs:%r' %(func_ids,set(Checklist)|set(FILE_UNSAFE_FUNCS)))
        if set(func_ids)&(set(SOURCE)|set(FILE_UNSAFE_FUNCS)):
            for value in arg.get('args'):
                parent, topids = {}, []
                rec_get_attr_top_id(value, parent, topids)
                #logger.warn("parent:%r,topids:%r" %(parent, topids))
                #logger.warn("value:%r," %(value))
                if topids and 'self' in topids[0].lower() :
                    leafs.append(topids[0])
                elif topids and topids[0].lower() != 'request' and topids[0].lower() != 'self':
                    leafs.append(topids[0])
                    #logger.warn("1parent:%r,topids:%r" %(parent, topids))
                elif topids and parent and parent.get('type')=='Attribute' and parent.get('attr') in REQUEST_VAR:
                    leafs.append(topids[0])
                    #logger.warn("2parent:%r,topids:%r" %(parent, topids))

            for arg_item in arg.get('args'):
                find_arg_leafs(arg_item, leafs)
        if arg.get('func') and arg.get('func').get('type') != 'Name':
            find_arg_leafs(arg.get('func'), leafs)
    if _type == 'Subscript':
        find_arg_leafs(arg.get('value'), leafs)
    if _type == "BinOp" and fields:
        if "right" in fields:
            if arg.get('right').get('type') == "Name":
                right_id = arg.get("right").get("id")
                if right_id:
                    leafs.append(right_id)
            elif arg.get('right').get('type') == 'Tuple':
                for elt in arg.get('right').get('elts'):
                    find_arg_leafs(elt, leafs)
            elif arg.get('right').get('type') == 'Call':
                find_arg_leafs(arg.get('right'), leafs)

        if "left" in fields and not arg.get("left").get("_fields"):
            left_id = arg.get('left').get('id')
            if left_id:
                leafs.append(left_id)
        if "left" in fields and arg.get("left").get("_fields"):
            find_arg_leafs(arg.get("left"), leafs)
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
        elif operand.get('type') == 'UnaryOp':
            rec_find_args(operand.get('operand'), args)
        elif operand.get('type') == 'BinOp':
            find_arg_leafs(operand, args)
    else:
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


