#!/usr/bin/env python
from setuptools import setup, find_packages

# versioneer config
import versioneer
versioneer.versionfile_source = 'httpsig/_version.py'
versioneer.versionfile_build = 'httpsig/_version.py'
versioneer.tag_prefix = 'v'                 # tags are like v1.2.0
versioneer.parentdir_prefix = 'httpsig-'    # dirname like 'myproject-1.2.0'

# create long description
with open('README.rst') as file:
    long_description = file.read()
with open('CHANGELOG.rst') as file:
    long_description += '\n\n' + file.read()

setup(
    name='httpsig',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description="Secure HTTP request signing using the HTTP Signature draft specification",
    long_description=long_description,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords='http,authorization,api,web',
    author='Adam Knight',
    author_email='adam@movq.us',
    url='https://github.com/ahknight/httpsig',
    license='MIT',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=True,
    install_requires=['pycrypto', 'six'],
    test_suite="httpsig.tests",
)
