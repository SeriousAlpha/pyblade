
import os
from pyblade import scan

FILE = 'taintanalysis.py'
#FILE = 'sample2.py'

dir = os.path.abspath('.')
file = os.path.join(dir, 'tests/' + FILE)
fd = open(file, 'r+')
strings = fd.read()


files = {
    FILE: strings}


res = scan(files)
print res
