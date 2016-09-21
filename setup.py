# -*- coding:utf-8 -*-
import codecs
import os
try:
    from setuptools import setup, find_packages
except:
    from distutils.core import setup

from execute_cmd import AUTHOR, AUTHOR_EMAIL, VERSION, URL


def read(fname):
    return codecs.open(os.path.join(os.path.dirname(__file__), fname)).read()

NAME = "executecmd"

DESCRIPTION = "execute remote command. "

LONG_DESCRIPTION = read("README.rst")

KEYWORDS = "execute command"

LICENSE = "MIT"

MODULES = ["execute_cmd"]

setup(
    name = NAME,
    version = VERSION,
    description = DESCRIPTION,
    long_description = LONG_DESCRIPTION,
    classifiers = [
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
    ],
    entry_points={
        'console_scripts': [
            'exec-cmd = execute_cmd:main',
        ],
    },
    keywords = KEYWORDS,
    author = AUTHOR,
    author_email = AUTHOR_EMAIL,
    url = URL,
    license = LICENSE,
    py_modules = MODULES,
    install_requires=["multi-thread-closing", "paramiko==2.0.2"],
    include_package_data=True,
    zip_safe=True,
)