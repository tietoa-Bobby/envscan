from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='envscan',
    version='0.1.0',
    description='Scan .env files for sensitive information or misconfigurations',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='tietoa-Bobby',
    url='https://github.com/tietoa-Bobby/envscan',
    packages=find_packages(),
    install_requires=[],
    extras_require={
        'dev': [
            'pytest>=6.0',
            'pytest-cov>=2.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'envscan=envscan.cli:main',
        ],
    },
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords='security, environment, secrets, scanning, cli',
    project_urls={
        'Bug Reports': 'https://github.com/tietoa-Bobby/envscan/issues',
        'Source': 'https://github.com/tietoa-Bobby/envscan',
        'Documentation': 'https://github.com/tietoa-Bobby/envscan#readme',
    },
) 