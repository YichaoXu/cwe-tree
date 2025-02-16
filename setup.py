from setuptools import setup, find_packages

setup(
    name="cwe_tree",  # 你的包名
    version="1.0.0",  # 版本号
    author="Yichao Xu",
    author_email="yxu166@jhu.edu",
    description="A Python package for querying CWE trees",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/YichaoXu/cwe-tree",  # GitHub 项目地址
    packages=find_packages(),
    package_data={"cwe_tree": ["data/*.csv"]},
    include_package_data=True,  # 包含 `data/` 目录下的 CSV 文件
    install_requires=[],  # 你的包的依赖项（如果有）
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
