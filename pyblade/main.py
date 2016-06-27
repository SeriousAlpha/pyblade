# !env python
# coding=utf-8
#
#
#      main.py
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

import dump_python
import logging
import color_log
import json
import os
import re
import traceback
import sys
import subprocess
#import cfg_generate
from optparse import OptionParser
from collections import OrderedDict

logger = color_log.init_log(logging.DEBUG)
# DEBUG INFO WARNING ERROR CRITICAL
DEBUG = True
ALERT = False

args_ori = set([])
is_arg_in = False
is_arg_return_op = False

Checklist = ['os.system','os.popen','eval','open','evec','popen','execfile','os.spawnl','os.spawnlp','os.spawnlpe','os.spawnle',\
        'os.spawnv','os.spawnve','os.spawnvp','os.spawnvpe','os.execv','os.execve','os.execvp',\
        'os.execvpe','os.open', 'os.popen2','os.popen3', 'os.popen4','os.putenv', 'os.rename',\
        'os.renames','call','Popen','Popen2','getoutput','getstatusoutput','eval','open','file']
Sensilist = ['sys.argv','socket.read']
FILE_UNSAFE_FUNCS = set()
FILE_SQL_UNSAFE_FUNCS = set()
used_import_files = []
import_func_all = {}
CMD_COUNT = 0
VAR_COUNT = 0
FUNC_COUNT = 0

class Check_func(object):
    """judge the injection base on ast"""
    def __init__(self, filename, check_type):
        try:
            self.tree = dump_python.parse_json(filename)
        except Exception,e:
            self.tree = "{}"
            print e
        self.tree = json.loads(self.tree)
        rec_decrease_tree(self.tree)
        #logger.debug("tree\n%r\n"%(self.tree))
        if DEBUG:
            try:
                fd = open(filename+".json",'w')
                json.dump(self.tree, fd)
                fd.flush()
                fd.close()
            except:
                pass
        self.filename = self.tree.get("filename")
        #logger.debug("filename::%r"%self.filename)
        self.body = self.tree.get("body")
        self.func = {}
        self.funcs = {}
        self.summary = {}
        self.func_lines = {}
        self.taint_top = []
        self.taint_func_top = []
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
        self.arg = {}
        self.taint_var = set()
        self.taint_func = set()
        self.taint_dests = set()
        #logger.debug("filename:%s"%(self.filename))

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
                #print "110:%r"%self.func
            elif obj.get('type') == 'ClassDef':
                self.get_func_objects(obj.get('body'), obj.get('name'))
        return

    def get_func_lines(self, func, func_name):
        """ get the line of the function"""
        #if "body" in func
        if isinstance(func, dict) and 'body' in func:
            lines = func.get('body')
            #logger.debug('body:%r'%lines)
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
                #print 'wish is come!%r'%self.func_lines
                continue
            elif line.get('type') == 'Call':
                self.func_lines[func_name].append(line)
                continue
            #print self.func_lines
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
        #logger.debug("function_name:%s" %(func_name))
        args_ori = set([arg.get('id') for arg in func.get('args').get("args")]) #arg.id
        if class_name and self.arg.get(class_name):
            arg_tmp = set(self.arg.get(class_name))
            args_ori = args_ori | arg_tmp
        #logger.debug("args:%s" %str(args_ori))
        self.func_lines.setdefault(func_name, [])
        #logger.debug("func_lines:%r" %(self.func_lines))
        self.get_func_lines(func, func_name)
        #logger.debug("func_lines:%r" %(lines))
#        if analyse_all:
        look_up_arg(func, args_ori, arg_leafs, func_name, self.import_func, self.check_type.get('verbose'))
        if func_name == '__init__':
            self.arg.setdefault(class_name, args_ori)
#        self.record_param.setdefault(func_name, args_ori)
        self.record_param[func_name] = args_ori # ??????
        #if not analyse_all:
        #    print 'func,record_param:', func_name,self.record_param.get(func_name)
        lines = self.func_lines[func_name]
        #对所有有函数执行的语句做进一步处理
        for line in lines:
            # print "all:%r" %(line)
            # print "*"*20
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

                #logger.info("arg_leafs:%r" %(arg_leafs))
                #logger.info("func_ids:%r" %(func_ids))
                #logger.info("record_param:%r" %(self.record_param.get(func_name)))
#                if analyse_all:
#                    look_up_arg(func, args_ori, arg_leafs,func_name)
#                print "UNTREATED_FUNS", UNTREATED_FUNS
                if self.check_type.get('cmd') and func_ids and (func_ids & (set(Checklist))) and arg_leafs:
                    #print "line221:%s"%func_ids
                    if set(arg_leafs) & set(self.record_param.get(func_name)):
                        #print self.record_param
                        if not is_arg_return_op and func_name not in ("__init__"):
                            FILE_UNSAFE_FUNCS.add(func_name)
                            self.record_unsafe_func.setdefault(lineno, {'func_name':func_name, 'args':args_ori, 'func_ids':func_ids,'arg_leafs':arg_leafs })
                            CMD_COUNT = CMD_COUNT + 1
                            #print CMD_COUNT

    def parse_py(self):
        self.get_func_objects(self.body)

        for key, func in self.func.iteritems():
            #logger.debug('%r,%r',key, func)
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
                print "locate the taint sink function : %s"%( self.lines[key - 1])

                if 'request' in value.get('arg_leafs'):
                    logger.critical("maybe injected File:%s,line:%s,function:%s--->%r" %(self.filename, key, value.get('func_name'), value.get('func_ids')))

        for key,value in self.record_other_unsafe_func.iteritems():
            logger.error("File:%s,line:%s,function:%s,dangerous_func:%r" %(self.filename, key, value.get('func_name'), value.get('func_ids')))

            print self.lines[key - 1]


    def record_taint_source(self):
        ''' tiant source marked '''
        valset = []
        global VAR_COUNT
        if 'sys.argv' in Sensilist:
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
                            except Exception,e:
                                pass
                            try:
                                if isinstance(ops, dict) and ops.get('right').get('value').get('attr') == 'argv' \
                                        and ops.get('right').get('value').get('value').get('id') == 'sys':
                                    lineno = ops.get('right').get('value').get('lineno')
                                    print "locate at lineno:%d  the taint source :  %s "%(lineno, self.lines[lineno - 1])
                            except Exception,e:
                                pass
        VAR_COUNT = VAR_COUNT + 1


    def find_function_def(self, body):
        for obj in body:
            if obj.get("type") == "FunctionDef":
                key = obj.get('name') + ":"
                self.find_function_def(obj.get('body'))
                self.funcs.setdefault(key, obj)
                print key,obj


    def find_function_expr(self, funcs):
        func_call = {}
        assign_stat = {}
        for key, value in funcs.iteritems():
            for arg in value.get('args').get('args'):
                argument = arg.get('id')
                self.summary.setdefault(key, {"argument": argument})
            for types in value.get('body'):
                type_ = types.get('type')
                if type_ == "Assign":
                    if types.get('value').get('type') == 'BinOp':
                        pass
                    for target in types.get('targets'):
                        dest = target.get('id')
                    #print dest

                if type_ == "FunctionDef":
                    for obj in types.get('body'):
                        type_t = obj.get('type')
                        if type_t == "Assign":
                            #print obj.get('value')
                            pass
                        if type_t == "Expr":
                            pass
                            #print obj.get('value')

                if type_ == "Expr":
                    if types.get('value').get('type') == 'Call':
                        func_id = types.get('value').get('func').get('id')
                        for arg in types.get('value').get('args'):
                            id_ = arg.get('id')
                        func_call.setdefault(func_id, id_)
                    #print func_call

        #print self.summary


    '''def find_args_leafs(self, args):
        for arg in args:
            self.find_args_leafs(arg)
            print arg
'''


    def store_sensitive_route(self):
        '''to record the taint route'''
        global FUNC_COUNT
        for expr in self.body:
            if expr.get("type") == "If":
                for str in expr.get("body"):
                    if str.get("type") == "Expr" and str.get("value").get("type") == "Call":
                        for args in str.get("value").get("args"):
                            if args.get("id") == self.taint_var:
                                self.taint_func = str.get("value").get("func").get("id")
                                self.taint_func_top = [self.taint_func]
        FUNC_COUNT = FUNC_COUNT + 1



    def find_taint_func(self):
        global ALERT
        global VAR_COUNT
        for func in self.body:
            if func.get("type") == "FunctionDef" and func.get("name") == self.taint_func:
                #print "line 278 match!"
                for arg in func.get('args').get("args"):
                    var = arg.get('id')
                self.taint_top.append(var)
                for body in func.get("body"):
                    if body.get("type") == "Assign":
                        ops = body.get("value").get("right")
                        try:
                            if ops.get("id") == self.taint_top[VAR_COUNT]:
                                for ids in body.get("targets"):
                                    self.taint_dests = ids.get("id")
                                    self.taint_top.append(self.taint_dests)
                        except:
                            pass

                    if body.get("type") == "Expr" and body.get("value").get("type") == "Call":
                        self.taint_func_top.append(body.get('value').get('func').get('id'))
                        for dest in body.get("value").get("args"):
                            if self.taint_dests == dest.get("id"):
                                ALERT = True
                            else:
                                ALERT = False
            #logger.debug('%r',self.taint_func_top[FUNC_COUNT])
            #print func.get('name')
            if func.get("type") == "FunctionDef" and func.get('name') == self.taint_func_top[-1]:
                print "True"
            #    print func.get('name')
            #    print func

        VAR_COUNT = VAR_COUNT + 1
        #logger.debug('find taint func')

    #todo: temp variable problem
    def call_function(self):
        self.record_taint_source()
        #logger.debug("record taint source")
        # self.find_function_def(self.body)
        self.find_function_expr(self.funcs)

        self.store_sensitive_route()
        self.find_taint_func()

class Path_node(object):
    pass

class Path(object):
    pass

def find_all_leafs(args, leafs):

    for arg in args:
        find_arg_leafs(arg, leafs)
'''
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
        #处理普通方法
        if value_func_type == 'Name' and (set(value_arg_ids)&args_ori):
            for func_id in set(import_func.keys())&value_func_ids:
                value_func_ids.add(import_func.get(func_id))
                value_func_ids.remove(func_id)

        elif target_ids:
            args_ori.difference_update(target_ids)
            #logger.warn("In Assign,Call delete (%r) from (%r) where line=(%r)" %(target_ids,args_ori,value.get('lineno')))
'''
def find_arg_leafs(arg, leafs):
    """通过递归找到全所有子节点,历史原因复数格式不修正"""
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
        elif topids and parent and parent.get('type')=='Attribute' and parent.get('attr') in REQUEST_VAR:
            leafs.append(topids[0])
            #logger.warn("2parent:%r,topids:%r" %(parent, topids))
        #find_arg_leafs(arg.get('value'), leafs)
    if _type == "Name":
        leafs.append(arg.get('id'))
    if _type == 'Call':
        func_ids = []
        rec_get_func_ids(arg.get('func'), func_ids)
        #logger.info('func_ids:%r,funcs:%r' %(func_ids,set(Checklist)|set(FILE_UNSAFE_FUNCS)))
        if set(func_ids)&(set(Checklist)|set(FILE_UNSAFE_FUNCS)):
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

'''
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
                #logger.info("is_arg_return:%r" %(line))
                return
        if ast_body:
            is_arg_return(ast_body, args_ori)
'''

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

'''
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
'''

def rec_get_targets(targets, out_targets):
    """recursive to find the target"""
    for target in targets:
        if target.get('type') == 'Subscript':
            rec_get_targets([target.get('value')], out_targets)
            #logger.debug("Subsrcipt %r" % out_targets)
        elif target.get('type') == 'Name':
            out_targets.append(target.get('id'))
            #logger.debug("Name %r" % out_targets)
        elif target.get('type') == 'Attribute':
            if target.get('value').get('type') == 'Name' and target.get('value').get('id') == 'self':
                out_targets.append('self.'+target.get('attr'))
                #logger.debug("Attribute %r" % out_targets)
    return

def look_up_arg(func, args_ori, args, func_name, import_func, verbose):
    """
    recursive to judge the args of unsafe function entrance.
    func : to be tested function
    args_ori : the arguments of to be tested function
    args : the arguments of unsafe function
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
        #print 'look_up_arg:line:',line
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
            #处理字符串拼接过程
        if line.get("type") == "Assign" and "value" in line and line.get("value").get("type")=="BinOp":
#            right = line.get('value').get('right')
#            if right.get('type') == 'Tuple':
#                rec_find_args(right.get('elts'))
            leafs = []
            find_arg_leafs(line.get("value"), leafs)
            #logger.warning('args_ori%r,leafs[]:%r' %(args_ori, leafs))
            if (set(args_ori)&set(leafs)):
                if target_ids:
                    args_ori.update(target_ids)
                    #logger.warning("In Assign,BinOp add (%r) to (%r) where line=(%r) line=(%r)" %(target_ids,args_ori,line.get('lineno'), line))
        if line.get("type") == "Assign" and "value" in line and line.get("value").get("type")=="Name":
            if target_ids and line.get("value").get("id") in args_ori:
                args_ori.update(target_ids)
                #logger.info("In Assign,Name add (%r) to (%r) where line=(%r) line=(%r)" %(target_ids,args_ori,line.get('lineno'), line))

        if line.get("type") == "Assign" and "value" in line and line.get("value").get("type")=="Attribute":
            value_func = line.get('value').get('value')
            if value_func and value_func.get("type") == 'Name':
                if target_ids and value_func.get("id") in args_ori:
                    args_ori.update(target_ids)
                    #logger.info("In Assign,Attr add (%r) to (%r) where line=(%r) line=(%r)" %(target_ids,args_ori,line.get('lineno'), line))

            else:
                topids = []
                parent = {}
                rec_get_attr_top_id(value_func, parent, topids)
                if (set(topids)&set(args_ori)):
                    if topids and topids[0].lower() == 'request':
                        if parent and parent.get('type')=='Attribute' and parent.get('attr') in REQUEST_VAR:
                            args_ori.update(target_ids)
                            #logger.info("In Assign,Attr add (%r) to (%r) where line=(%r) line=(%r)" %(target_ids,args_ori,line.get('lineno'), line))
                        elif parent and parent.get('type')=='Attribute':
                            args_ori.difference_update(set(target_ids))
                            #logger.warn("In Assign,Attr delete (%r) from (%r) where line=(%r)***************************** line=(%r)" %(target_ids,args_ori,line.get('lineno'), line))



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


def usage():
    print """用途：本程序主要用于测试py代码中命令注入\n用法：python main.py -d path
        path即为需要测试的目录路径"""

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
        #print "filename",filename
        try:
            judge_all(filename, check_type)
        except Exception, e:
            print filename
            traceback.print_exc()


def judge_all(filename, check_type):
    global used_import_files
    try:
        judge = Check_func(filename, check_type)
        #print judge.import_module
        for import_file, value in judge.import_module.iteritems():
            if import_file and import_file not in used_import_files:
                used_import_files.append(import_file)
                judge_all(import_file, check_type)
        judge.parse_py()
        judge.call_function()
        judge.record_all_func()

    except:
        traceback.print_exc()


if __name__ == "__main__":
    #cfg = cfgGenerate.ControlFlowGraph()
    #s_ast = cfg.parse_file(fn)
    #cfgGenerate.PrintCFG(s_ast)
    main()

