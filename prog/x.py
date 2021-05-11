#!/usr/bin/env python

import os; os.environ['PWNLIB_SILENT']='1'

import random
import sys
import os

from pwn import *

p = None


OBFV = True #irrelevant
OBFP = True
OBFD = True

pvector = []


def sendprompt(i):
    if not OBFP:
        p.csendline(str(i).encode("utf-8"))
    else:
        p.csendline(pvector[i])

def splitspace(tstr):
    utfstr = tstr.decode("utf-8")
    return [x.encode("utf-8") for x in utfstr.split(" ")]


def splitline(tstr):
    utfstr = tstr.decode("utf-8")
    return [x.encode("utf-8") for x in utfstr.split("\n")]


def rnd():
    sendprompt(1)
    res = p.crecvuntil(drnd*3); print(repr(res))
    r = splitspace(splitline(res)[-2])[-1]
    p.crecvuntil(drnd+b" ")
    return r


def sign(m):
    sendprompt(8)
    p.crecvuntil(drnd+b" ")
    p.csendline(m)
    res = p.crecvuntil(drnd*3); print(repr(res))
    r, s = splitspace(splitline(res)[-2])[-2:]
    p.crecvuntil(drnd+b" ")
    return r, s

def verifyfixed(r, s):
    sendprompt(10)
    p.crecvuntil(drnd+b" ")
    p.csendline(r)
    p.crecvuntil(drnd+b" ")
    p.csendline(s)
    res = p.crecvuntil(drnd*3); print(repr(res))


    if b"flag" in res:
        p.crecvuntil(drnd+b" ")
        return (True, [l for l in splitline(res) if b"OOO" in l][0])
    else:

        assert splitspace(splitline(res)[1])[0] == pvector[5]
        challenge_m = splitspace(splitline(res)[1])[1]

        assert splitspace(splitline(res)[3])[0] == pvector[7]
        g = splitspace(splitline(res)[3])[1]


        p.crecvuntil(drnd+b" ")
        return (False, challenge_m, g)

def sinv(v):
    sendprompt(2)
    p.crecvuntil(drnd+b" ")
    p.csendline(v)
    res = p.crecvuntil(drnd*3); print(repr(res))
    r = splitspace(splitline(res)[-2])[-1]
    p.crecvuntil(drnd+b" ")
    return r


def minv(v):
    sendprompt(3)
    p.crecvuntil(drnd+b" ")
    p.csendline(v)
    res = p.crecvuntil(drnd*3); print(repr(res))
    r = splitspace(splitline(res)[-2])[-1]
    p.crecvuntil(drnd+b" ")
    return r


def mul(v1, v2):
    sendprompt(5)
    p.crecvuntil(drnd+b" ")
    p.csendline(v1)
    p.crecvuntil(drnd+b" ")
    p.csendline(v2)
    res = p.crecvuntil(drnd*3); print(repr(res))
    r = splitspace(splitline(res)[-2])[-1]
    p.crecvuntil(drnd+b" ")
    return r


def sum(v1, v2):
    sendprompt(4)
    p.crecvuntil(drnd+b" ")
    p.csendline(v1)
    p.crecvuntil(drnd+b" ")
    p.csendline(v2)
    res = p.crecvuntil(drnd*3); print(repr(res))
    r = splitspace(splitline(res)[-2])[-1]
    p.crecvuntil(drnd+b" ")
    return r


def exp_mod_p(v1, v2):
    sendprompt(7)
    p.crecvuntil(drnd+b" ")
    p.csendline(v1)
    p.crecvuntil(drnd+b" ") 
    p.csendline(v2)
    res = p.crecvuntil(drnd*3); print(repr(res))
    r = splitspace(splitline(res)[-2])[-1]
    p.crecvuntil(drnd+b" ")
    return r


def crecv(self, n):
    res = self.recv(n)
    self.history += res
    return res


def b1(ip=None, port=None):
    if not ip:
        p = process("./s.py")
    else:
        p = remote(ip, port)
    res = p.recvuntil(b"\n")
    assert b"Welcome" in res
    p.sendline(b"")
    b1 = p.recv(1)
    assert b1!=b''
    print("OK")


def b2(ip=None, port=None):
    global p
    global drnd
    global pvector

    def crecv(n):
        res = p.recv(n)
        p.history += res
        return res

    def crecvuntil(tstr):
        assert type(tstr) == bytes
        res = p.recvuntil(tstr)
        p.history += res
        return res

    def csendline(tstr):
        assert type(tstr) == bytes
        p.sendline(tstr)
        p.history += tstr+b"\n"

    if not ip:
        p = process("./s.py")
    else:
        p = remote(ip, port)
    p.history = b""
    p.crecv = crecv
    p.crecvuntil =  crecvuntil
    p.csendline = csendline

    p.history = b""
    p.crecv = crecv
    p.crecvuntil =  crecvuntil
    p.csendline = csendline

    p.crecvuntil(b"\n")
    p.csendline(b"")

    if not OBFD:
        drnd = b">"
        p.crecv(1)
    else:
        drnd = p.crecv(3)
        print(repr(drnd))

    res = p.crecvuntil(drnd*2); print(repr(res))
    res = p.crecvuntil(drnd+b" "); print(repr(res))
    pvector = splitline(res)

    v1 = rnd()
    v1_minus = sinv(v1)
    zero = sum(v1, v1_minus)
    v1_inv = minv(v1)
    one = mul(v1, v1_inv)
    vt = sum(zero, one)#1
    vt = sum(vt, one)
    two = vt
    vt = sum(vt, one)
    three = vt
    vt = sum(vt, one)
    vt = sum(vt, one)
    vt = sum(vt, one) #6
    six1 = vt
    vt = sum(vt, one)
    vt = sum(vt, one)
    vt = sum(vt, one)
    six2 = mul(two, three)
    _ = exp_mod_p(three, two)

    try:
        os.unlink("interaction1.txt")
    except OSError:
        pass
    h = p.history
    t1 = 0
    t2 = h[:h.rfind(pvector[7])].rfind(pvector[7])-1
    with open("interaction1.txt", "wb") as fp:
        fp.write(h[t1:t2])
    print("OK")


def b3(ip=None, port=None):
    global p
    global drnd
    global pvector

    if not ip:
        p = process("./s.py")
    else:
        p = remote(ip, port)

    def crecv(n):
        res = p.recv(n)
        p.history += res
        return res

    def crecvuntil(tstr):
        assert type(tstr) == bytes
        res = p.recvuntil(tstr)
        p.history += res
        return res

    def csendline(tstr):
        assert type(tstr) == bytes
        p.sendline(tstr)
        p.history += tstr+b"\n"

    p.history = b""
    p.crecv = crecv
    p.crecvuntil =  crecvuntil
    p.csendline = csendline

    p.crecvuntil(b"\n")
    p.csendline(b"")

    if not OBFD:
        drnd = b">"
        p.crecv(1)
    else:
        drnd = p.crecv(3)
        print(repr(drnd))


    res = p.crecvuntil(drnd*2); print(repr(res))
    res = p.crecvuntil(drnd+b" "); print(repr(res))
    pvector = splitline(res)

    m1 = rnd()
    k_as_m2 = rnd()
    r, s = sign(m1) #assuming they used m2 as k

    ks = mul(k_as_m2, s)
    m1_minus = sinv(m1)
    ks_minus_m1 = sum(ks, m1_minus)
    r_inv = minv(r)
    x = mul(r_inv, ks_minus_m1)

    _, challenge_m, g = verifyfixed(r, s)
    sign(challenge_m)
    assert p.history.decode("utf-8").split("\n")[-14] == "Not allowed!"
    print("OK")


def exploit(ip=None, port=None):
    global p
    global drnd
    global pvector


    gg=0
    while True:
        gg+=1
        if not ip:
            p = process("./s.py")
        else:
            p = remote(ip, port)

        def crecv(n):
            res = p.recv(n)
            p.history += res
            return res

        def crecvuntil(tstr):
            assert type(tstr) == bytes
            res = p.recvuntil(tstr)
            p.history += res
            return res

        def csendline(tstr):
            assert type(tstr) == bytes
            p.sendline(tstr)
            p.history += tstr+b"\n"

        p.history = b""
        p.crecv = crecv
        p.crecvuntil =  crecvuntil
        p.csendline = csendline

        p.crecvuntil(b"\n")
        p.csendline(b"")

        if not OBFD:
            drnd = b">"
            p.crecv(1)
        else:
            drnd = p.crecv(3)
            print(repr(drnd))


        res = p.crecvuntil(drnd*2); print(repr(res))
        res = p.crecvuntil(drnd+b" "); print(repr(res))
        pvector = splitline(res)

        m1 = rnd()
        k_as_m2 = rnd()
        r, s = sign(m1) #assuming they used m2 as k

        ks = mul(k_as_m2, s)
        m1_minus = sinv(m1)
        ks_minus_m1 = sum(ks, m1_minus)
        r_inv = minv(r)
        x = mul(r_inv, ks_minus_m1)

        _, challenge_m, g = verifyfixed(r, s)
        print(challenge_m, g, x)

        xr = mul(x, r)
        xr_plus_m = sum(challenge_m, xr)
        k_inv = minv(k_as_m2)
        s = mul(k_inv, xr_plus_m)

        f, *flag = verifyfixed(r, s)
        if not f:
            if type(p) == pwnlib.tubes.process.process:
                p.kill()
            else:
                p.close()
            continue
        flag = flag[0]
        break


    print("Found in", gg, "tries")


    if type(p) == pwnlib.tubes.process.process:
        p.kill()
    else:
        p.close()
    print("FLAG:", flag.decode("utf-8"))

    try:
        os.unlink("interaction2.txt")
    except OSError:
        pass
    token = b"This is the flag:\n"
    h = p.history
    t2 = h.rfind(token)+len(token)
    t1 = h[:h.rfind(drnd*3)].rfind(drnd*3)
    cut_string = h[t1:t2]
    assert b"OOO" not in cut_string
    assert b"Welcome" not in cut_string
    assert b"This is" in cut_string
    with open("interaction2.txt", "wb") as fp:
        fp.write(cut_string)
 


if __name__ == "__main__":
    if len(sys.argv)>1:
        if len(sys.argv)>2:
            ip = sys.argv[2]
            port = sys.argv[3]
        else:
            ip = port = None
        if sys.argv[1] == "b1":
            b1(ip, port)
        elif sys.argv[1] == "b2":
            b2(ip, port)
        elif sys.argv[1] == "b3":
            b3(ip, port)
        elif sys.argv[1] == "ex":
            exploit(ip, port)
    else:
        exploit()





