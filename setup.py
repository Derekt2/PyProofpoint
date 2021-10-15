import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pyproofpoint",
    version="1.0.0",
    author="Derek Thomas2",
    author_email="derek.e.thomas@biola.edu",
    maintainer='Derek Thomas2',
    description="A python wrapper for proofpoint's threat insight API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Derekt2/PyProofpoint",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: Internet',
    ],
    python_requires='>=3.5',
    install_requires=[
   'requests'
   ]
)