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
    'pycrypto',
    'six'
]

if sys.version_info > (3,):
    requires.append('dnspython3')
else:
    requires.append('dnspython')

# commit 9f1c3988b64d4d95868825ecc48b00c1474bbf37 in PySocks
# introduced udp support. First available version is 1.5.6
pysocks = 'PySocks>=1.5.6'
extras_require = {
    'test': ['mock', pysocks],
    'socks': [pysocks]
}

tests_requires = requires + extras_require['test']

setup(
    name="dnsknife",
    version=version,
    packages=find_packages(),
    description="DNS tools",
    url="https://github.com/gandi/dnsknife",
    author="Gandi",
    author_email="feedback@gandi.net",
    license="GPLv3",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Internet :: Name Service (DNS)',
        'Intended Audience :: Developers',
    ],
    install_requires=requires,
    tests_require=tests_requires,
    test_suite='dnsknife.tests',
    extras_require=extras_require,
    keywords='dns lookup dnssec tpda rdap',
)
