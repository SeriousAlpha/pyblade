
import os
from pyblade import scan

dir = os.path.abspath('.')
file = os.path.join(dir, 'tests/taintanalysis.py')
fd = open(file, 'r+')
strings = fd.read()


files = {
    'taintanalysis.py': strings}


res = scan(files)
print res
