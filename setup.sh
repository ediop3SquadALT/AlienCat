#!/bin/bash

set -e

sudo apt update
sudo apt install -y python3 python3-pip python3-venv build-essential libssl-dev libffi-dev python3-dev python3-setuptools libsqlite3-dev liblzma-dev

python3 -m pip install --upgrade pip

python3 -m pip install \
  psutil \
  cryptography \
  prompt_toolkit
