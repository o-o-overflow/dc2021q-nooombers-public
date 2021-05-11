#!/usr/bin/env python


import random
import sys
from Crypto.PublicKey import DSA
from Crypto.Util import number
from Crypto.Cipher import AES
import hashlib



aeskey = random.randrange(0, 0x100000000000000000000).to_bytes(16, byteorder="big")
aesiv = random.randrange(0, 0x100000000000000000000).to_bytes(16, byteorder="big")
cipher = AES.new(aeskey, AES.MODE_CBC, IV=aesiv)





GRND = 7
MAXTRIES = 14

OBFV = True
OBFP = True
OBFD = True

challenge_m = 11223344556677889900177756

dvector = [chr(x) for x in range(0x9a00, 0x9a00+0x100)]
drnd = random.choice(dvector)
pvector = [chr(x) for x in range(0x9b00, 0x9b00+0x100)]
random.shuffle(pvector)


class State:
    def __init__(self, obf=False):
        self.dsakey = DSA.generate(1024) #, randfunc=wrandom)
        self.rndv = [random.randint(1000000000,self.dsakey.q-1000000000) for _ in range(GRND)]
        self.obf = obf

gstate = None


def get_dirs(odir):
    if not OBFD:
        if odir == 1:
            return ""
        elif odir == 2:
            return ">"
    else:
        if odir == 1:
            return ""
        elif odir == 2:
            return drnd


def mangle_prompt(v):
    if not OBFP:
        return str(v)
    else:
        return pvector[int(v)]


def mangle_value(v):
    if not OBFV:
        return str(v)
    else:
        s = v.to_bytes(130, byteorder="big")
        cipher = AES.new(aeskey, AES.MODE_CBC, IV=aesiv)
        sf =    b"B"*4+hashlib.sha256(s).digest()[:3]+\
                s+\
                hashlib.sha256(s).digest()[:3]+b"X"*4
        cs = cipher.encrypt(sf)
        tstr = ""
        for c in cs:
            tstr += chr(0x9c00+c)

        return tstr


def mprint(prompt=None, values=None, hiddenv=False):
    tstrl = []

    if prompt != None:
        tstrl.append(mangle_prompt(prompt))
    if values != None:
        for v in values:
            vstr = mangle_value(v)
            if hiddenv:
                vstr = "*"*len(str(vstr))
            tstrl.append(vstr)

    print(" ".join(tstrl))


def mprintinit():
    print(get_dirs(2)*3)


def geto(vmin=1, vmax=11):
    p = get_dirs(2)
    istr = input(p+" ")
    assert(len(istr)<100)

    if not OBFP:
        v = int(istr)
    else: #this is prompt
        v = pvector.index(istr)
    assert(v>=vmin and v<=vmax)
    return v


def getn(ivn=None, hiddenv=False):
    p = get_dirs(2)
    istr = input(p+" ")
    assert(len(istr)<200)

    if not OBFV:
        v = int(istr)
    else:
        tstr2 = b""
        for x in istr:
            tstr2+=bytes([ord(x)-0x9c00])
        decipher = AES.new(aeskey, AES.MODE_CBC, IV=aesiv)
        ds = decipher.decrypt(tstr2)
        assert ds[:4] == b"B"*4
        assert ds[-4:] == b"X"*4
        d = ds[4+3:-(4+3)]
        return int.from_bytes(d, byteorder="big")
    return v


def o1(hiddenv=False): #rnd
    vo = random.choice(gstate.rndv)
    mprint(prompt=1, values=[vo], hiddenv=hiddenv)
    return vo


def o3(v=None, hiddenv=False): #minv
    if v==None:
        v = getn()
    vo = number.inverse(v, gstate.dsakey.q)
    mprint(prompt=3, values=[v, gstate.dsakey.q, vo], hiddenv=hiddenv)
    return vo


def o2(v=None, hiddenv=False): #sinv
    if v==None:
        v = getn()
    vo = (-1*v) % gstate.dsakey.q
    mprint(prompt=2, values=[v, gstate.dsakey.q, vo], hiddenv=hiddenv)
    return vo


def o5(v1=None, v2=None, hiddenv=False): #mul
    if v1==None:
        v1 = getn()
    if v2==None:
        v2 = getn()
    vo = ((v1*v2) % gstate.dsakey.q)
    mprint(prompt=5, values=[v1, v2, gstate.dsakey.q, vo], hiddenv=hiddenv)
    return vo


def o4(v1=None, v2=None, hiddenv=False): #sum
    if v1==None:
        v1 = getn()
    if v2==None:
        v2 = getn()
    vo = ((v1+v2) % gstate.dsakey.q)
    mprint(prompt=4, values=[v1, v2, gstate.dsakey.q, vo], hiddenv=hiddenv)
    return vo


def o6(v1=None, v2=None, hiddenv=False): #mul mod p
    if v1==None:
        v1 = getn()
    if v2==None:
        v2 = getn()
    vo = ((v1*v2) % gstate.dsakey.p)
    mprint(prompt=6, values=[v1, v2, gstate.dsakey.p, vo], hiddenv=hiddenv)
    return vo


def o7(v1=None, v2=None, hiddenv=False): #exp mod p
    if v1==None:
        v1 = getn()
    if v2==None:
        v2 = getn()
    vo = (pow(v1,v2,gstate.dsakey.p))
    mprint(prompt=7, values=[v1, v2, gstate.dsakey.p, vo], hiddenv=hiddenv)
    return vo


def o8(): #sign
    m = getn()
    if m == challenge_m:
        print("Not allowed!")
        return
        #sys.exit(3)

    while True:
        k = o1(hiddenv=True)
        r_long = o7(gstate.dsakey.g, k, hiddenv=True)
        rnd_tmp = o1(hiddenv=True)
        rnd_tmp_inv = o2(rnd_tmp, hiddenv=True)
        r = o4(o4(r_long, rnd_tmp, hiddenv=True), rnd_tmp_inv, hiddenv=True)
        if r!=0: break

    while True:
        xr = o5(gstate.dsakey.x, r, hiddenv=True)
        xr_plus_m = o4(m, xr, hiddenv=True)
        k_inv = o3(k, hiddenv=True)
        s = o5(k_inv, xr_plus_m, hiddenv=True)
        if s!=0: break

    mprint(prompt=8, values = [m, r, s])


def o9(): #verify, arbitrary message
    m = getn()
    r = getn()
    s = getn()
    
    w = o3(s)
    u1 = o5(m, w)
    u2 = o5(r, w)
    v_1 = o7(gstate.dsakey.g, u1)
    v_2 = o7(gstate.dsakey.y, u2)
    v_long = o6(v_1, v_2)
    rnd_tmp = o1()
    rnd_tmp_inv = o2(rnd_tmp)
    v = o4(o4(v_long, rnd_tmp), rnd_tmp_inv)

    mprint(prompt=9, values = [m, r, s, v])


def o10(): #verify, fixed message
    m = challenge_m
    r = getn()
    s = getn()
    
    w = o3(s)
    u1 = o5(m, w)
    u2 = o5(r, w)
    v_1 = o7(gstate.dsakey.g, u1)
    v_2 = o7(gstate.dsakey.y, u2)
    v_long = o6(v_1, v_2)
    rnd_tmp = o1()
    rnd_tmp_inv = o2(rnd_tmp)
    v = o4(o4(v_long, rnd_tmp), rnd_tmp_inv)

    mprint(prompt=10, values = [m, r, s, v])

    #print(v, r)
    if v == r:
        print("Correct signature! This is the flag:")
        with open("flag", "rb") as fp:
            print(fp.read().decode("utf-8").strip())


def o11(): #exit
    mprint(prompt=9)
    sys.exit(0)


def main():
    global gstate

    #print(gstate.dsakey.x, gstate.dsakey.y, gstate.dsakey.p, gstate.dsakey.q)

    print("Welcome to nooombers! Press enter to start...")
    a = input()
    gstate=State()

    gg = 0
    while True:
        gg+=1
        if gg==MAXTRIES+1:
            print("Too much! Disabling one option...")
            #sys.exit(4)      
        mprintinit()
        mprint(prompt=1) #rnd
        mprint(prompt=2) #sinv
        mprint(prompt=3) #minv
        mprint(prompt=4) #sum
        mprint(prompt=5) #mul
        mprint(prompt=6) #mul mod p
        mprint(prompt=7) #exp mod p
        mprint(prompt=8) #sign
        mprint(prompt=9) #verify arbitrary
        if not (gg>MAXTRIES):
            mprint(prompt=10) #verify fixed
        mprint(prompt=11) #exit

        v = str(geto())
        if gg>MAXTRIES:
            assert v!=str(10)  
        globals()["o"+v]()


if __name__ == "__main__":
    main()


