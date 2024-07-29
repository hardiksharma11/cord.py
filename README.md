# CORD.py
CORD.py is a Python library that provides a collection of classes and methods to interact with the Cord blockchain network.

## Building the SDK

To build the SDK and see changes, follow these steps:

1. Clone this repository to your local machine:

   ```bash
   git clone <repository_url>
   cd <repository_directory>

2. Make sure you have python installed. You can download it from [here](https://www.python.org/downloads/). After that install setuptools using:
     ```bash
     pip install setuptools

3. Install dependencies and setup modules using setup.py :

     ```bash
     python setup.py install

## Required Dependencies
- [substrate-interface](https://polkascan.github.io/py-substrate-interface/)
- [base58](https://pypi.org/project/base58/)
- [mnemonic](https://pypi.org/project/mnemonic/)
- [pynacl](https://pypi.org/project/PyNaCl/)

## Experimenting with SDK Methods
## Demo Methods
Once the SDK is built, you can experiment with the provided methods.

## Statement Method:

The `demo-statement` method allows you to interact with statement-related functionalities.

To run the statement demo, execute the following command:

```bash
python -u "demo/src/func_tests.py"
```

The output of each demo script will demonstrate the functionality of the corresponding method. For a detailed structure of the demo scripts, refer to the source code.

