from ubuntu:18.04

run apt-get -qq update && apt-get install -qq --no-install-recommends xinetd rsyslog software-properties-common

run add-apt-repository -y ppa:ubuntu-toolchain-r/ppa
run apt-get install -y python3.7
run apt-get install -y python3-pip

run python3.7 -m pip install pip
run python3.7 -m pip install -U pip
run python3.7 -m pip install pwntools
run python3.7 -m pip install pycrypto pycryptodome pycryptodomex


run apt install -y netcat-traditional htop

copy exploit.sh /
copy test1.sh /
copy test2.sh /
copy test3.sh /
copy x.py /


