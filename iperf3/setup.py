'''
Author: lihui
Date: 2025-04-01 16:55:40
LastEditTime: 2025-04-01 16:55:59
LastEditors: lihui
Description: 
'''
from setuptools import setup, find_packages

setup(
    name="iperf3-tester",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "iperf3",
        "tkinter",
    ],
    entry_points={
        'console_scripts': [
            'iperf3-tester=iperf3_tester:main',
        ],
    },
) 