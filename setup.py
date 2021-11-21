import setuptools
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

if os.name == "nt":
	raise RuntimeError("You can't install this package on windows machine!")

setuptools.setup(
    name="LenHTTP",
    version="2.2.4",
    author="lenforiee",
    author_email="lenforiee@gmail.com",
    description="An powerful web framework written from scratch!",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lenforiee/LenHTTP",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)
