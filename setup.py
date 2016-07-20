
from distutils.core import setup

setup(
      name="pyblade",
      version="0.0.2",
      description="python source auto audit",
      author="H. Y.",
      url="http://http://gitlab.task.ac.cn/vdg/pyblade",
      license="GNU",
      author_email='huangyong@iscas.ac.cn',
      packages= ['pyblade.analyser', 'pyblade.conf', 'pyblade.summary', 'pyblade.utils', 'pyblade.traversers'],  #find packages
      #package_dir={'pyblade': 'pyblade'},
      #entry_points={'console_scripts': ['pyblade = pyblade.pyblade:main']},
      #scripts=["scripts/main.py"],
      platforms="Independant",
      py_modules=['pyblade.cfg_generate']  #listing individual modules
      )

