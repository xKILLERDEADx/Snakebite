from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="snakebite-scanner",
    version="2.0.0",
    author="Muhammad Abid",
    author_email="spaceworkofficial@gmail.com",
    description="Advanced automated web security scanner with 219+ attack modules",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/xKILLERDEADx/Snakebite",
    packages=find_packages(),
    py_modules=["snakebite", "banner"],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "snakebite=snakebite:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
    ],
    keywords="security scanner vulnerability web penetration-testing",
    license="MIT",
    project_urls={
        "Bug Tracker": "https://github.com/xKILLERDEADx/Snakebite/issues",
        "Documentation": "https://github.com/xKILLERDEADx/Snakebite#readme",
        "Source Code": "https://github.com/xKILLERDEADx/Snakebite",
    },
)
