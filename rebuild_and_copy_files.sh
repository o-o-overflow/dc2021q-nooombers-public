#!/bin/bash

rm public_bundle.tar.gz
rm prog/interaction1.txt
rm prog/interaction2.txt
rm service/interaction1.txt
rm service/interaction2.txt
rm service/s.py
rm service/flag
rm interaction/x.py
rm interaction1.txt
rm interaction2.txt

(
    cd prog
    ./x.py b1 || { echo 'b1 failed' ; exit 1; }
    ./x.py b2 || { echo 'b2 failed' ; exit 1; }
    ./x.py ex || { echo 'ex failed' ; exit 1; }
)

cp prog/x.py interaction/
cp prog/s.py service/
cp prog/flag service/
cp prog/interaction1.txt interaction1.txt
cp prog/interaction2.txt interaction2.txt
