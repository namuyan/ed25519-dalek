from setuptools import setup
from setuptools_rust import Binding, RustExtension
import os.path

with open('README.md', mode="r", errors='ignore') as f:
    readme = f.read()

version = '0.1.0-unknown'
with open("Cargo.toml", mode="r") as fp:
    for line in fp.read().split("\n"):
        if not line.startswith("version"):
            continue
        _, version = line.split("=", 2)
        version = version.lstrip().rstrip()
        version = version[1:]
        version = version[:-1]
        break

setup(
    name="nem-ed25519-rust",
    long_description=readme,
    long_description_content_type='text/markdown',
    version=version,
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Rust",
    ],
    rust_extensions=[
        RustExtension("nem_ed25519_rust", features=['pylib'], binding=Binding.PyO3)
    ],
    # rust extensions are not zip safe, just like C-extensions.
    include_package_data=True,
    license="BSD-3",
    zip_safe=False,
)
