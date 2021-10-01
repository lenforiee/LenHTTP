import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="LenHTTP",
    version="2.2.2",
    author="Lenforiee",
    author_email="lenforiee@misumi.me",
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
