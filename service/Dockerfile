from ubuntu:18.04

run apt-get -qq update && apt-get install -qq --no-install-recommends xinetd rsyslog software-properties-common

run add-apt-repository -y ppa:ubuntu-toolchain-r/ppa
run apt-get install -y python3.7
run apt-get install -y python3-pip
run python3.7 -m pip install pip
run python3.7 -m pip install pycrypto pycryptodome pycryptodomex

run apt install -y netcat-traditional htop

copy flag /flag
copy service.conf /service.conf
copy banner_fail /banner_fail
copy wrapper /wrapper
copy s.py /server.py

expose 8765
cmd ["/usr/sbin/xinetd", "-filelog", "/dev/stderr", "-dontfork", "-f", "/service.conf"]

