# CORD.py
CORD.py is a Python library that provides a collection of classes and methods to interact with the Cord blockchain network.

## Prerequisites for Building the SDK

Before you begin, ensure that you have the following:

1. **Python 3.10 or higher**:
   - CORD.py requires Python version 3.10 or higher. You can check your Python version by running:
     ```bash
     python3 --version
     ```

   - If you do not have Python installed, you can download it from the [official Python website](https://www.python.org/downloads/).

2. **pip**:
   - pip is the package installer for Python. It is usually included with Python, but you can verify its installation with:
     ```bash
     pip3 --version
     ```

   - If pip is not installed, you can install it by following these steps:
     
       ```bash
       sudo apt install python3-pip
       ```
     

3. **Setuptools**:
   - Setuptools is required to manage the installation of Python packages. Install it using:
     ```bash
     pip3 install setuptools
     ```

## Building the SDK

To build the SDK and see changes, follow these steps:

1. **Clone the repository**:
   - Clone this repository to your local machine and navigate to the directory:
     ```bash
     git clone <repository_url>
     cd <repository_directory>
     ```

2. **Install dependencies and set up modules**:
   - Use the `setup.py` script to install dependencies and set up the modules:
     ```bash
     python3 setup.py install
     ```

## Required Dependencies

CORD.py relies on several Python libraries. These dependencies will be installed when you run the `setup.py` script:

- [substrate-interface](https://polkascan.github.io/py-substrate-interface/)
- [base58](https://pypi.org/project/base58/)
- [mnemonic](https://pypi.org/project/mnemonic/)
- [pynacl](https://pypi.org/project/PyNaCl/)

## Experimenting with SDK Methods

After building the SDK, you can experiment with the provided methods.

### Demo Methods

The SDK includes demo methods to help you interact with the Cord blockchain network.

### Statement Method:

The `demo-statement` method allows you to interact with statement-related functionalities.

To run the statement demo, execute the following command:

```bash
python3 -u "demo/src/func_tests.py"
