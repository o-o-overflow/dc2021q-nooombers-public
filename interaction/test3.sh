#!/bin/bash

export TERM=linux
export TERMINFO=/etc/terminfo
python3.7 -u ./x.py b3 "$1" "$2"

