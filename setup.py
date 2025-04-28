from setuptools import setup, find_packages

setup(
    name="cataclysmdns",
    version="0.1.0",
    description="Ferramenta modular de pentest DNS",
    author="Daniel Silva",
    python_requires=">=3.8",
    packages=find_packages(include=["core", "core.*", "utils", "utils.*"]),
    py_modules=["cli", "config"],
    include_package_data=True,
    install_requires=[
        "dnspython>=2.4.2",
        "aiohttp>=3.8.5",
        "typer>=0.9.0",
        "rich>=14.0.0",
        "python-dotenv>=1.0.0",
        "beautifulsoup4>=4.12.2",
        "certifi>=2023.7.22",
        "typing-extensions>=4.8.0",
        "cachetools>=5.3.2"
    ],
    entry_points={
        "console_scripts": [
            "cataclysm=cli:app",
        ]
    },
)