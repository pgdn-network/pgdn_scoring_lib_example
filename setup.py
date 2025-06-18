#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="pgdn-scoring",
    version="1.0.0",
    description="PGDN Private Scoring Library for DePIN Infrastructure Scanner",
    author="Simon Morley",
    author_email="sm@pgdn.network",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        # Add any dependencies your scorer needs
        # "requests>=2.25.0",
        # "numpy>=1.20.0",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
