#todo: to make the install setup.py file

from distutils.core import setup

setup(
      name="pyblade",
      version="0.0.1",
      description="python source auto audit",
      author="H. Y.",
      url="http://http://gitlab.task.ac.cn/vdg/pyblade",
      license="GNU",
      author_email='huangyong@iscas.ac.cn',
      packages= ['pyblade','pyblade.analyser','pyblade.conf','pyblade.summary','pyblade.utils'],
      #package_dir={'pyblade': 'pyblade'},
      #entry_points={'console_scripts': ['pyblade = pyblade.pyblade:main']},
      #scripts=["scripts/main.py"],
      zip_safe=False,
      platforms="Independant",
      #py_modules=['pysonar', 'lists']
      )
