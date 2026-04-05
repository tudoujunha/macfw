from pathlib import Path

from setuptools import find_packages, setup


PROJECT_ROOT = Path(__file__).parent
README = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
VERSION_NS: dict[str, str] = {}
exec((PROJECT_ROOT / "macfw" / "__init__.py").read_text(encoding="utf-8"), VERSION_NS)


setup(
    name="macfw",
    version=VERSION_NS["__version__"],
    description="A small pf-based firewall manager for macOS with a ufw-like CLI",
    long_description=README,
    long_description_content_type="text/markdown",
    author="tudoujun",
    python_requires=">=3.9",
    packages=find_packages(include=["macfw", "macfw.*"]),
    entry_points={
        "console_scripts": [
            "macfw=macfw.cli:main",
        ]
    },
)
