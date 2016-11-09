#!/bin/sh
# Installing Volatility

virtualenv volatility
cd volatility
source bin/activate
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility/
pip install distorm3 yara pycrypto pillow openpyxl ujson
python ./setup.py install
vol.py --info


# vol.py imageinfo -f memdump.raw
# vol.py <command> --profile=<profile> -f memdump.raw