
# from setuptools import setup, find_packages
# import os

# # Read requirements
# def read_requirements():
#     req_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
#     if os.path.exists(req_path):
#         with open(req_path, 'r') as f:
#             return [line.strip() for line in f if line.strip() and not line.startswith('#')]
#     return [
#         "click>=8.0.0",
#         "pandas>=1.3.0", 
#         "sentence-transformers>=2.0.0",
#         "tidb-vector>=0.0.9",
#         "python-dotenv>=0.19.0",
#         "openpyxl>=3.0.9",
#     ]

# setup(
#     name="argus",
#     version="1.0.0",
#     author="Joyce Wambui",
#     author_email="jwambui@protonmail.com",
#     description="AI-powered security scanner for machine learning projects",
#     long_description="Argus - AI-powered security analysis for ML projects",
#     url="https://github.com/prehistoricpancake/argus",
#     packages=find_packages(exclude=['tests*', 'frontend*']),
#     classifiers=[
#         "Development Status :: 4 - Beta",
#         "Intended Audience :: Developers",
#         "Programming Language :: Python :: 3",
#         "Programming Language :: Python :: 3.8",
#         "Programming Language :: Python :: 3.9",
#         "Programming Language :: Python :: 3.10",
#         "Programming Language :: Python :: 3.11",
#     ],
#     python_requires=">=3.8",
#     install_requires=read_requirements(),
#     entry_points={
#         'console_scripts': [
#             'argus=argus_cli.cli:cli'
#         ],
#     },
#     include_package_data=True,
#     zip_safe=False,
# )

from setuptools import setup, find_packages
import os

# Read the README file
def read_long_description():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    req_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(req_path):
        with open(req_path, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return [
        "click>=8.0.0",
        "pandas>=1.3.0", 
        "sentence-transformers>=2.0.0",
        "tidb-vector>=0.0.9",
        "python-dotenv>=0.19.0",
        "openpyxl>=3.0.9",
        "PyMySQL>=1.0.0",
        "requests>=2.25.0",
        "pathlib2>=2.3.0;python_version<'3.4'",
    ]

setup(
    name="argus-ai-security",
    version="1.0.0",
    author="Joyce Wambui",
    author_email="jwambui@protonmail.com",
    description="AI-powered security scanner for machine learning projects",
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/prehistoricpancake/argus",
    project_urls={
        "Bug Tracker": "https://github.com/prehistoricpancake/argus/issues",
        "Documentation": "https://github.com/prehistoricpancake/argus#readme",
        "Source Code": "https://github.com/prehistoricpancake/argus",
    },
    packages=find_packages(exclude=['tests*', 'frontend*', '*.egg-info']),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.812",
        ],
        "frontend": [
            "flask>=2.0.0",
            "flask-cors>=3.0.0",
        ]
    },
    entry_points={
        'console_scripts': [
            'argus=argus_cli.cli:cli'
        ],
    },
    include_package_data=True,
    package_data={
        'data': ['*.xlsx'],  # Include sample data files if needed
    },
    zip_safe=False,
    keywords="ai security machine-learning vulnerability scanner artificial-intelligence",
)