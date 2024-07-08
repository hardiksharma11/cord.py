from setuptools import setup, find_packages

setup(
    name='cord.py',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'substrate-interface',
        'base58'
    ],
)
