from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    rust_extensions=[RustExtension("aleo.aleo", binding=Binding.PyO3)],
)
