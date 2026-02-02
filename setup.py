from setuptools import setup, find_packages

setup(
    name='kiss-osint',
    version='1.0.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'aiohttp',
        'aiohttp-socks',
        'rich',
        'phonenumbers',
        'geopy',
        'hashid',
    ],
    entry_points={
        'console_scripts': [
            'kiss=kiss.__main__:main',
        ],
    },
)
