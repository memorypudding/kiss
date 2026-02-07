from setuptools import setup, find_packages

setup(
    name="xsint",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "aiohttp",
        "aiohttp-socks",
        "rich",
        "phonenumbers",
        "geopy",
        "hashid",
        "httpx",
        "gitfive",
        "ghunt",
        "intelx",
    ],
    entry_points={
        "console_scripts": [
            "xsint=xsint.__main__:main",
        ],
    },
)
