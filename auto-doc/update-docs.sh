#!/usr/env/bin bash

set -e

source venv/bin/activate

cd auto-doc
pip install -r requirements.txt
cd ..

cd src
python ./update_docs.py