把python文件改成字符串的代码，从而实现Python文件的‘不落地’分析。

```python
import os
dir = os.path.abspath('.')
file = os.path.join(dir, 'tests\\taintanalysis.py')
fd = open(file, 'r+')
fd.read()
```

