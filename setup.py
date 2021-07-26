from setuptools import setup, find_packages
import os, shutil

version = '0.2'

setup(name='poodledo',
      version=version,
      description='a Python library for working with Toodledo',
      scripts=[
          'bin/cycle',
          'bin/tdcli',
          'bin/too',
      ],
      long_description='''poodledo is a Python library for working with the web-based task management software [Toodledo](http://www.toodledo.com).''',
      classifiers=[
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'License :: OSI Approved :: BSD License',
          'Operating System :: Unix',
          'Development Status :: 5 - Production/Stable',
      ],
      keywords='toodledo api',
      author='Adam Compton',
      author_email='comptona@gmail.com',
      url='https://github.com/handyman5/poodledo',
      install_requires = ['parsedatetime', 'python-dateutil'],
      packages = ['poodledo'],
      license='BSD-3-Clause',
      zip_safe=False,
)
