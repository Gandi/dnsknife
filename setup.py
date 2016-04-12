from setuptools import setup, find_packages

requires = [
    'requests',
    'dnspython',
    'PySocks>=1.5.6',
    'pycrypto'
]

setup(
    name = "dnsknife",
    version = "0.1",
    packages = find_packages(),
    description = "DNS tools",
    install_requires = requires
)
