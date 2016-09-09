#!env python
#coding = utf-8
import sys
import os


def test(num):
    def func1(funcs, arg):
        return funcs(arg)

    def _get_func():
        return test_func

    def func2(arg):
        func = _get_func()
        func(arg)

    def func6():
        pass

    def func4():
        func2('123')

        def func5():
            pass
        func5()
        func6()

    func4()
    func2(cmd)
    build_airport()
    #if 1 == num:
    #    def func3():
    #        print 'func3'
    #    if True:
    #        def func7():
    #            pass
    #        def func8():
    #            pass
    #    return func1
    #elif 2 == num:
    #    return func2


def build_airport():
    def func9():
        pass


def test_func(cmd):
    os.system(cmd)

if __name__ == '__main__':
    cmd = sys.argv[1]
    func = test(1)
    func(test_func, cmd)
    func = test(2)
    func(cmd)
    sys.exit(0)
