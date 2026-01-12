"""
Setup script для AP-Guardian
"""

from setuptools import setup, find_packages

setup(
    name="ap-guardian",
    version="1.0.0",
    description="Система активной сетевой защиты для OpenWrt",
    author="AP-Guardian Team",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.4.5",
    ],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "ap-guardian=src.main:main",
        ],
    },
)
