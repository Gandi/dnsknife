import sys
import os
import re

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'dnsknife/__init__.py')) as v_file:
    version = re.compile(r".*__version__ = '(.*?)'",
                         re.S).match(v_file.read()).group(1)


requires = [
    'requests',
    'PySocks>=1.5.6',
    'pycrypto',
    'six'
]

if sys.version_info > (3,):
    requires.append('dnspython3')
else:
    requires.append('dnspython')

extras_require = {
   'test': ['mock']
}

tests_requires = requires + extras_require['test']

setup(
    name="dnsknife",
    version=version,
    packages=find_packages(),
    description="DNS tools",
    install_requires=requires,
    tests_require=tests_requires,
    test_suite='dnsknife.tests',
)
