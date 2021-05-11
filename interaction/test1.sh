#!/bin/bash

export TERM=linux
export TERMINFO=/etc/terminfo
python3.7 -u ./x.py b1 "$1" "$2"

