#todo: to make the install setup.py file

from setuptools import setup, find_packages
setup(
      name="pyblade",
      version="0.0.1",
      description="python source auto audit",
      author="H. Y.",
      url="http://http://gitlab.task.ac.cn/vdg/pyblade",
      license="GNU",
      packages= find_packages(),
      scripts=["scripts/main.py"],
      )

