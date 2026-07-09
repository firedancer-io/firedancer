#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="agave-cluster",
    version="0.1.0",
    description="Agave cluster management CLI tool",
    author="Firedancer Contributors",
    packages=find_packages(),
    install_requires=[
        "click>=8.0.0",
        "pyyaml>=6.0",
        "requests>=2.25.0",
    ],
    entry_points={
        "console_scripts": [
            "agave-cluster=agave_cluster.cli:main",
        ],
    },
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
