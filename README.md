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
   - Setuptools is required to manage the installation of Python packages. First, check if it is already installed:
     ```bash
     pip show setuptools
     ```
   - If it is not installed, you can install it using:
     ```bash
     pip3 install setuptools
     ```

## Building the SDK

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


3. Make sure you have python installed. You can download it from [here](https://www.python.org/downloads/). After that install setuptools using:
     ```bash
     pip install setuptools

4. Install dependencies and setup modules using setup.py :


5. **Setuptools**:
   - Setuptools is required to manage the installation of Python packages. First, check if it is already installed:
     ```bash
     pip show setuptools
     ```
   - If it is not installed, you can install it using:
     ```bash
     python setup.py install


## Required Dependencies
- substrate-interface
- base58
- mnemonic
- pynacl


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
     
## Experimenting with SDK Methods

After building the SDK, you can experiment with the provided methods.

### Demo Methods

The SDK includes demo methods to help you interact with the Cord blockchain network.

### Statement Method:

The `demo-statement` method allows you to interact with statement-related functionalities.

To run the statement demo, execute the following command:

```bash
python3 -u "demo/src/func_tests.py"
