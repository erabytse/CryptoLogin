# setup.py
from setuptools import setup, find_packages

setup(
    name="cryptologin",
    version="1.0.0",
    description="Zero-Knowledge Authentication System",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="CryptoLogin erabytse Team",
    author_email="contact@cryptologin.io",
    url="https://github.com/erabytse/cryptologin.git",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
    ],
    install_requires=[
        "fastapi>=0.104.0",
        "uvicorn>=0.24.0",
        "flash512-vanguard>=2.1.1",
        "pydantic>=2.5.0",
        "python-multipart>=0.0.6",
        "slowapi>=0.1.9",
    ],
    extras_require={
        "dev": ["pytest", "pytest-cov", "httpx"],
        "postgres": ["psycopg2-binary"],
        "full": ["psycopg2-binary", "redis"],
    },
)