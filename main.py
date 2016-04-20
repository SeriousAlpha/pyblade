#!env python
# coding=utf-8
#
#
# FileName:  main.py
#
# Description:
#
#

import dump_python
import logging
import color_log
import json
import os
import re
import traceback
import sys
import subprocess
from optparse import OptionParser
from collections import OrderedDict

logger = color_log.init_log(logging.ERROR)
DEBUG = False

args_ori = set([])
is_arg_in = False
is_arg_return_op = False

Checklist = ['os.system','os.popen','eval','open']
FILE_UNSAFE_FUNCS = set()
FILE_SQL_UNSAFE_FUNCS = set()
used_import_files = []
import_func_all = {}
CMD_COUNT = 0

class CheckFunc(object):
    """根据语法树自动判断注入攻击"""
    def __init__(self, filename, check_type):
        try:
            self.tree = dump_python.parse_json(filename)
        except Exception,e:
            self.tree = "{}"
            print e
        self.tree = json.loads(self.tree)
        rec_decrease_tree(self.tree)
        if DEBUG:
            try:
                fd = open(filename+".json",'w')
                json.dump(self.tree, fd)
                fd.flush()
                fd.close()
            except:
                pass
        self.filename = self.tree.get("filename")
        self.start = self.tree.get("start")
        self.body = self.tree.get("body")
        self.func = {}
        self.func_lines = {} #
        self.check_type = check_type
        with open(self.filename, 'r') as fd:
            self.lines = fd.readlines()
        self.unsafe_func = set()
        self.untreated_func = set()
        self.record_unsafe_func = OrderedDict({})
        self.record_other_unsafe_func = OrderedDict({})
        self.import_module = {}
        self.record_param = {}
        self.import_func = {}
        self.arg = {} #主要用于获取类的参数
        logger.debug("filename:%s"%(self.filename))
        
    def get_func_objects(self, body, class_name=None):
        """get function struct """
        for obj in body:
            if obj.get("type") == "FunctionDef":
                if class_name:
                    key = obj.get('name')+":"+class_name
                else:
                    key = obj.get('name')+":"
                self.func.setdefault(key,obj)
                logger.debug("func:%r"%(obj))
            elif obj.get('type') == 'ClassDef':
                self.get_func_objects(obj.get('body'),obj.get('name'))
        return

    def get_func_lines(self, func, func_name):
        """ 获取函数的执行的行，找到func"""
        #if "body" in func
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
            #print "line:",line
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
                    self.get_func_lines(ast_test.get('left'),func_name)
            if ast_test and ast_test.get('type') == 'BoolOp':
                for value in ast_test.get('values'):
                    if value.get('comparators'):
                        self.get_func_lines(value.get('comparators'),func_name)
                    if value.get('left'):
                        self.get_func_lines(value.get('left'), func_name)

            if ast_args:
                self.get_func_lines(ast_args, func_name)
        #print "line:",line
        return

    def parse_func(self, func, class_name, analyse_all):
        global leafs
        global args_ori
        global is_arg_in
        global CMD_COUNT
        global is_arg_return_op
        is_arg_return_op = False
        arg_leafs = []
        func_name = func.get("name")
        logger.debug("function_name:%s" %(func_name))
        args_ori = set([arg.get("id") for arg in func.get('args').get("args")]) #arg.id
        if class_name and self.arg.get(class_name):
            arg_tmp = set(self.arg.get(class_name))
            args_ori = args_ori|arg_tmp
        logger.debug("args:%s" %str(args_ori))
        self.func_lines.setdefault(func_name, [])
        self.get_func_lines(func, func_name)
        lines = self.func_lines[func_name]
        logger.debug("func_lines:%r" %(lines))
#        if analyse_all:
        look_up_arg(func, args_ori, arg_leafs,func_name, self.import_func, self.check_type.get('verbose'))
        if func_name == '__init__':
            self.arg.setdefault(class_name, args_ori)
#        self.record_param.setdefault(func_name, args_ori)
        self.record_param[func_name] = args_ori
        if not analyse_all:
            print 'func,record_param:', func_name,self.record_param.get(func_name)

        #对所有有函数执行的语句做进一步处理
        for line in lines:
            #print "all:%r" %(line)
#            print "*"*20
            arg_leafs = []
            is_arg_in = False
            value = line.get("value")
            lineno = line.get("lineno")
            if (value and value.get("type") == "Call") or (line and line.get('type') == 'Call'):
                logger.debug("value:%r" %(value))
                line_func = value.get("func") if value else line.get('func')
                line_func = value if value and value.get('type')=='Call' else line
                value_args = value.get('args') if value else line.get('args')
                value = value if value else line
                func_ids = []
                rec_get_func_ids(line_func, func_ids)
                func_ids = set(func_ids)
                rec_find_args(value, arg_leafs)

                logger.info("arg_leafs:%r" %(arg_leafs))
                logger.info("func_ids:%r" %(func_ids))
                logger.info("record_param:%r" %(self.record_param.get(func_name)))
#                if analyse_all:
#                    look_up_arg(func, args_ori, arg_leafs,func_name)
#                print "UNTREATED_FUNS", UNTREATED_FUNS
                if self.check_type.get('cmd') and func_ids and (func_ids&((set(Checklist)|set(FILE_UNSAFE_FUNCS)))) and arg_leafs:
                    if self.check_type.get('verbose') and arg_leafs:
                        print "CMD--FILE:%s,FUNCTION:%s,LINE:%s" %(self.filename, func_name, lineno )
                    if set(arg_leafs)&set(self.record_param.get(func_name)):
                        if not is_arg_return_op and func_name not in ("__init__"):
                            FILE_UNSAFE_FUNCS.add(func_name)
                            self.record_unsafe_func.setdefault(lineno, {'func_name':func_name, 'args':args_ori, 'func_ids':func_ids,'arg_leafs':arg_leafs })
                            CMD_COUNT = CMD_COUNT + 1


    def parse_py(self):
        self.get_func_objects(self.body)

        for key,func in self.func.iteritems():
            self.parse_func(func, key.split(":")[1],True)

        for key, func in self.func.iteritems():
            self.parse_func(func, key.split(":")[1],False)
        for key, func in self.func.iteritems():
            self.parse_func(func, key.split(":")[1], False)

    def record_all_func(self):
        from copy import deepcopy
        record = {}
        tmp_record_unsafe_func = deepcopy(self.record_unsafe_func)
        for key, value in tmp_record_unsafe_func.iteritems():
            for func_id in value.get('func_ids'):
                for func in tmp_record_unsafe_func.values():
                    if func_id in func.get('func_name'):
                        record.setdefault(key, [value.get('func_name'),func_id,str(func.get('func_ids'))])

        for key, value in record.iteritems():
            logger.error("File:%s,line:%s,function:%s" %(self.filename, key, '--->'.join(value)))

        for key, value in self.record_unsafe_func.iteritems():
            logger.error("maybe injected File:%s,line:%s,function:%s--->%r" %(self.filename, key, value.get('func_name'), value.get('func_ids')))
            print self.lines[key - 1]
            if 'request' in value.get('arg_leafs'):
                logger.critical("maybe injected File:%s,line:%s,function:%s--->%r" %(self.filename, key, value.get('func_name'), value.get('func_ids')))

        for key,value in self.record_other_unsafe_func.iteritems():
            logger.error("File:%s,line:%s,function:%s,dangerous_func:%r" %(self.filename, key, value.get('func_name'), value.get('func_ids')))
            print self.lines[key - 1]

            #print "FILE_UNSAFE_FUNCS",FILE_UNSAFE_FUNCS

def find_all_leafs(args, leafs):

    for arg in args:
        find_arg_leafs(arg, leafs)

def find_func_leafs(value, args_ori, target_ids, import_func):
    """处理函数情况"""
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
        #处理普通方法
        if value_func_type == 'Name' and (set(value_arg_ids)&args_ori):
            for func_id in set(import_func.keys())&value_func_ids:
                value_func_ids.add(import_func.get(func_id))
                value_func_ids.remove(func_id)

        elif target_ids:
            args_ori.difference_update(target_ids)
            logger.warn("In Assign,Call delete (%r) from (%r) where line=(%r)" %(target_ids,args_ori,value.get('lineno')))


def find_arg_leafs(arg, leafs):
    """通过递归找到全所有子节点,历史原因复数格式不修正"""
    fields = arg.get("_fields")
    _type = arg.get('type')
    if _type == "Attribute":
        parent, topids = {}, []
        rec_get_attr_top_id(arg, parent, topids)
        logger.warn("parent:%r,topids:%r" %(parent, topids))
        if topids and 'self' in topids[0].lower() :
            leafs.append(topids[0])
        elif topids and topids[0].lower() != 'request' and topids[0].lower() != 'self':
            leafs.append(topids[0])
            logger.warn("1parent:%r,topids:%r" %(parent, topids))
        elif topids and parent and parent.get('type')=='Attribute' and parent.get('attr') in REQUEST_VAR:
            leafs.append(topids[0])
            logger.warn("2parent:%r,topids:%r" %(parent, topids))
        #find_arg_leafs(arg.get('value'), leafs)
    if _type == "Name":
        leafs.append(arg.get('id'))
    if _type == 'Call':
        func_ids = []
        rec_get_func_ids(arg.get('func'), func_ids)
        logger.info('func_ids:%r,funcs:%r' %(func_ids,set(Checklist)|set(FILE_UNSAFE_FUNCS)))
        if set(func_ids)&(set(Checklist)|set(FILE_UNSAFE_FUNCS)):
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

def is_arg_return(func, args_ori):
    """
        判断是否有对arg参数的可控性判断，比如判读是否数字，是否file等
    """
    global is_arg_return_op

    if isinstance(func, dict):
        lines = func.get('body')
    elif isinstance(func, list):
        lines = func

    for line in lines:
        is_return = False
        is_arg_in = False
        is_param = False
        ast_body = line.get('body')
        ast_orelse = line.get('orelse')
        ast_handlers = line.get('handlers')
        if line.get('type') == "If":
            for body in line.get('body'):
                if body.get('type') == "Return":
                    is_return = True
            test = line.get('test')
            if line.get('test') and line.get('test').get('type') == "UnaryOp":
                operand = line.get('test').get('operand')
                if operand:
                    args = []
                    rec_find_args(line.get('test'), args)
                    if set(args)&set(args_ori):
                        is_arg_in = True
            elif test and test.get('type') == 'Compare':
                args = []
                for key,value in test.iteritems():
                    if key == 'left':
                        if test[key].get('type') == 'Name':
                            args = [test[key].get('id')]
                    if key == 'comparators':
                        for comparator in test[key]:
                            if comparator.get('type') in ("List", 'Tuple'):
                                for elt in comparator.get('elts'):
                                    if elt.get('type') == 'Name':
                                        is_param = True

                if set(args)&set(args_ori) and not is_param:
                    is_arg_in = True

            is_arg_return_op = is_return&is_arg_in
            if is_arg_return_op:#找到即返回
                logger.info("is_arg_return:%r" %(line))
                return
        if ast_body:
            is_arg_return(ast_body, args_ori)

def rec_find_args(operand, args):
    if isinstance(operand, list) or isinstance(operand, tuple):
        find_all_leafs(operand, args)
    elif isinstance(operand, dict):
        if operand.get('type') == 'Call':
            if "args" in operand:
                find_all_leafs(operand.get('args'), args)
            if "value" in operand.get('func'):
                rec_find_args(operand.get('func').get('value'), args)
        elif operand.get('type') == 'UnaryOp':# not param判断中
            rec_find_args(operand.get('operand'), args)
        elif operand.get('type') == 'BinOp':
            find_arg_leafs(operand, args)
    else:
        return

def rec_get_attr_top_id(func, parent, ids):
    """
    func = {u'_fields': [u'value', u'attr_name'], u'type': u'Attribute', u'attr': u'get', u'value': {u'_fields': [u'value', u'attr_name'], u'type': u'Attribute', u'attr': u'POST', u'value': {u'type': u'Name', u'lineno': 15, u'id': u'request'}, u'lineno': 15}, u'lineno': 15}
    ids： 用于回传结果,只有一个
    """
    if func.get('type') == 'Name':
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

def rec_get_targets(targets, out_targets):
    """递归找出target"""
    for target in targets:
        if target.get('type') == 'Subscript':
            rec_get_targets([target.get('value')], out_targets)
        elif target.get('type') == 'Name':
            out_targets.append(target.get('id'))
        elif target.get('type') == 'Attribute':
            if target.get('value').get('type') == 'Name' and target.get('value').get('id')=='self':
                out_targets.append('self.'+target.get('attr'))

    return

def look_up_arg(func, args_ori, args, func_name, import_func, verbose):
    """递归找出危险函数中的参数是否属于函数参数入口的
      func 代表测试的函数,args_ori是要被测试的函数的参数，args则是危险函数中的参数
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
        #处理单纯属性
        if line.get('type') == 'Assign':
            target_ids = []
            rec_get_targets(line.get('targets'), target_ids)
        else:
            target_ids = []

        if line.get("type") == "Assign" and "value" in line and line.get("value").get("type")=="Name":
            if target_ids and line.get("value").get("id") in args_ori:
                args_ori.update(target_ids)
                logger.info("In Assign,Name add (%r) to (%r) where line=(%r) line=(%r)" %(target_ids,args_ori,line.get('lineno'), line))

        if line.get("type") == "Assign" and "value" in line and line.get("value").get("type")=="Attribute":
            value_func = line.get('value').get('value')
            if value_func and value_func.get("type") == 'Name':
                if target_ids and value_func.get("id") in args_ori:
                    args_ori.update(target_ids)
                    logger.info("In Assign,Attr add (%r) to (%r) where line=(%r) line=(%r)" %(target_ids,args_ori,line.get('lineno'), line))

            else:
                topids = []
                parent = {}
                rec_get_attr_top_id(value_func, parent, topids)
                if (set(topids)&set(args_ori)):
                    if topids and topids[0].lower() == 'request':
                        if parent and parent.get('type')=='Attribute' and parent.get('attr') in REQUEST_VAR:
                            args_ori.update(target_ids)
                            logger.info("In Assign,Attr add (%r) to (%r) where line=(%r) line=(%r)" %(target_ids,args_ori,line.get('lineno'), line))
                        elif parent and parent.get('type')=='Attribute':
                            args_ori.difference_update(set(target_ids))
                            logger.warn("In Assign,Attr delete (%r) from (%r) where line=(%r)***************************** line=(%r)" %(target_ids,args_ori,line.get('lineno'), line))


        if line.get('type') == 'Return' and 'value' in line and line.get('value'):
            value_id = line.get('value').get('id')
            if value_id and value_id in args_ori :
                print 'untrited_func_name',func_name
                UNTREATED_FUNS.add(func_name)

        if line.get('type') == 'For':
            iter_args = []
            find_arg_leafs(line.get('iter'), iter_args)
            if set(iter_args)&set(args_ori):
                targets = []
                find_arg_leafs(line.get('target'), targets)
                if targets:
                    args_ori.update(targets)
                    logger.info("In For Call add (%r) to (%r) where line=(%r) line=(%r)" %(target_ids,args_ori,line.get('lineno'), line))

        if line.get("type") == "Expr" and "value" in line and line.get("value").get("type")=="Call":
            value_arg_ids = []
            rec_find_args(line.get('value'), value_arg_ids)
            if set(value_arg_ids)&set(args_ori):
                is_arg_in = True

        if line.get('type') == 'Call': #处理if语句中中eval类似函数
            func_ids = []
            rec_get_func_ids(line.get('func'), func_ids)
            args_tmp = []
            rec_find_args(line, args_tmp)
            if (set(args_tmp)&args_ori) and func_ids and (set(func_ids)&(set(Checklist)|set(FILE_UNSAFE_FUNCS))):
                is_arg_in = True
                logger.info('type:call')
#        if line.get('type') == 'Ififif':
        if line.get('type') == 'If':
            is_if_return = False
            is_if_param = False
            is_in_param = False

            if_judge_func = set(['exists','isfile','isdir','isabs','isdigit'])
            for body in line.get('body'):
                if body.get('type') == 'Return':
                    is_if_return = True
            test = line.get('test')
            if test and test.get('type') == 'UnaryOp':
                operand = test.get('operand')
                args_tmp = []
                if operand:
                    rec_find_args(operand, args_tmp)
                    if set(args_tmp)&set(args_ori):
                        is_if_param = True
                func_ids = []
                rec_get_func_ids(operand, func_ids)
                if set(func_ids)&if_judge_func and is_if_return and is_if_param:
                    args_ori.difference_update(args_tmp)
                    logger.warn("In If delete (%r) from (%r) where line=(%r)***************************** type=(%r)" %(args_tmp,args_ori,test.get('lineno'),test.get('type')))

            if test and test.get('type') == 'Compare':
                args_tmp = []
                for key,value in test.iteritems():
                    if key == 'left':
                        if test[key].get('type') == 'Name':
                            args_tmp = [test[key].get('id')]
                    if key == 'comparators':
                        for comparator in test[key]:
                            if comparator.get('type') in ('List', 'Tuple'):
                                for elt in comparator.get('elts'):
                                    if elt.get('type') == 'Name' and elt.get('id') in args_ori:
                                        is_in_param = True
                if set(args_tmp)&set(args_ori) and is_if_return and not is_in_param:
                    args_ori.difference_update(args_tmp)
                    logger.warn("In If delete (%r) from (%r) where line=(%r)***************************** type=(%r)" %(args_tmp,args_ori,test.get('lineno'),test.get('type')))

        if ast_body:
            look_up_arg(ast_body, args_ori, args, func_name, import_func, verbose)
        if ast_orelse:
            look_up_arg(ast_orelse, args_ori, args, func_name, import_func, verbose)
        if ast_handlers:
            look_up_arg(ast_handlers, args_ori, args, func_name, import_func, verbose)
        if ast_test and ast_test.get('comparators'):
            look_up_arg(ast_test.get('comparators'),args_ori, args, func_name, import_func, verbose)
        if ast_test and ast_test.get('left'):
            look_up_arg(ast_test.get('left'),args_ori, args, func_name, import_func, verbose)
        if ast_args :
            look_up_arg(ast_args, args_ori, args, func_name, import_func, verbose)

    return

def get_func_id(func, func_ids):
    """获取被调用函数的名称"""
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

def rec_get_func_ids(func, func_ids):#处理连续的unicode.encode等
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

def get_pythonpaths():
    pythonpath = os.environ.get('PYTHONPATH')
    pythonpaths = [path for path in pythonpath.split(':') if 'python' not in path]

    return pythonpaths


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

def walk_dir(file_path, file_type='.py'):
    files = []
    if os.path.isfile(file_path):
        files = [file_path]
    elif os.path.isdir(file_path):
        for root, dirs, filenames in os.walk(file_path):
            for filename in filenames:
#                print 'walk_dir:filename', filename
                if re.match(".*\.py$", filename.strip()):
                    files.append(root+"/"+filename)
    return files

def print_func(filename, lineno):
    with open(filename, 'r') as fd:
        lines = fd.readlines()
        print lines[lineno-1]

def usage():
    print """用途：本程序主要用于测试py代码中命令注入\n用法：python main.py -d path
        path即为需要测试的目录"""

def main():
    parser = OptionParser()
    parser.add_option("-d", "--dir", dest="file_path",help="files to be checked")
    parser.add_option("-c", "--cmd", action="store_true", dest="cmd_check",help="cmd check", default=True)
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",help="print all unsafe func", default=False)
    (options, args) = parser.parse_args()
    file_path = options.file_path
    cmd_check = options.cmd_check
    verbose = options.verbose

    check_type = {'cmd':cmd_check,  'verbose':verbose}
    if not file_path:
        usage()
        sys.exit()
    else:
        if (os.path.isfile(file_path) or os.path.isdir(file_path)):
            files = walk_dir(file_path)
        else:
            print "您输入的文件或者路径不存在"
            sys.exit()
    for filename in files:
        print "filename",filename
        try:
            judge_all(filename, check_type)
        except Exception, e:
            print filename
            traceback.print_exc()

def judge_all(filename, check_type):
    global used_import_files
    try:
        judge = CheckFunc(filename, check_type)
        print judge.import_module
        for import_file, value in judge.import_module.iteritems():
            if import_file and import_file not in used_import_files:
                used_import_files.append(import_file)
                judge_all(import_file, check_type)
        judge.parse_py()
        judge.record_all_func()
    except:
        traceback.print_exc()




if __name__ == "__main__":

    main()







