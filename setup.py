import codecs
from setuptools import setup


with codecs.open('README.rst', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="shadowsocks",
    version="2.7.0",
    license='http://www.apache.org/licenses/LICENSE-2.0',
    description="A fast tunnel proxy that help you get through firewalls",
    author='clowwindy',
    author_email='clowwindy42@gmail.com',
    url='https://github.com/zhuanyi/shadowsocks',
    packages=['shadowsocks', 'shadowsocks.crypto'],
    package_data={
        'shadowsocks': ['README.rst', 'LICENSE']
    },
    install_requires=[],
    entry_points="""
    [console_scripts]
    sslocal = shadowsocks.local:main
    ssserver = shadowsocks.server:main
    sslink = shadowsocks.sslink:main
    ssconfig = shadowsocks.ssconfig:main
    """,
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: Proxy Servers',
    ],
    long_description=long_description,
)
