from setuptools import setup

requirements = ["kubernetes", "requests"]

setup(
    name="saml_test_helper",
    version="0.1.0",
    description="Companion saml_test_helper library for saml-test-idp",
    url="https://github.com/canonical/saml-test-idp",
    author="Weii Wang",
    author_email="weii.wang@canonical.com",
    packages=["saml_test_helper"],
    install_requires=requirements,
    package_data={"saml_test_helper": ["certs/*"]},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
