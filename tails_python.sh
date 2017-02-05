#!/bin/sh
# Install into TAILS (The Amnesic Incognito Live System) dependencies for decrypt_file.py
# TAILS can be downloaded from https://tails.boum.org
sudo apt-get -y update
sudo apt-get -y install build-essential libgmp3-dev python3-dev python3-pip
torify pip3 install --user PyCrypto
