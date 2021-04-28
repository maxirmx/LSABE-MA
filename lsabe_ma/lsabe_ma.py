import os
import sys
import random
from pathlib import Path

from base64 import b64encode, b64decode

# https://jhuisi.github.io/charm/cryptographers.html
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair,extract_key

from .formuleDeViete import formuleDeViete, polyVal
from .symcrypto import SymmetricCryptoAbstraction
from .serializer import SER, DES
from .accessPolicy import accessPolicy



class LSABE_MA():
    def __init__(self, msk_path, max_kw):

# These are file names to load\store MSK and PP
        self._msk_fname = msk_path.joinpath('lsabe-ma.msk')   
        self._pp_fname  = msk_path.joinpath('lsabe-ma.pp')
# The maximum number of keywords
        self._max_kw = max_kw   
# ....
# [charm crypto] For symmetric pairing G1 == G2  
        self.group = PairingGroup('SS512')

# 1 in ZR (a kind of ugly but I cannot think of better method)
        x = self.group.random(ZR) 
        self._1 = x/x       
       
# Access policy
        self._ap = accessPolicy()       

    @property
    def msk_fname(self):
        return str(self._msk_fname)

    @property
    def pp_fname(self):
        return str(self._pp_fname)

   

# ................................................................................
# GlobalSetup(κ)→(MSK,PP). Given the security parameter κ,Global setup algorithm  
# outputs public parameter PP for the system, global identity GID for the authorized 
# users and the master secret key MSK for each authority. 
# ................................................................................
#  GloablSetup
# ................................................................................
    def GlobalSetup(self):
        f = self.group.random(G1) 
        g = self.group.random(G1)
        lmbda = self.group.random(ZR)
        self._MSK = { 'lambda':lmbda }        
        self._PP =  { 'f':f, 'g':g, 'g^lambda':g ** lmbda }

#        print("Master secret key:")
#        print(self._MSK)
#        print("Public properties:")
#        print(self._PP)

        self.__serialize_G()


# ................................................................................
#  SystemLoad
#  Deserializes MSK and PP from files
# ................................................................................
    def GlobalLoad(self):
        self.__deserialize_G()

#        print("Master secret key:")
#        print(self._MSK)
#        print("Public properties:")
#        print(self._PP)

# ................................................................................
#  MSK and PP serializers and deserializers
# ................................................................................
    def __serialize_G(self):
        l = SER(self._msk_fname, self.group)
        l.p_val(self._MSK.values())

        l = SER(self._pp_fname, self.group)
        l.p_val(self._PP.values())

    def __deserialize_G(self):
        l = DES(self._msk_fname, self.group)
        self._MSK = {}
        (self._MSK['lambda'], ) = l.g_val(1)

        l = DES(self._pp_fname, self.group)
        self._PP = {}
        (self._PP['f'], self._PP['g'], self._PP['g^lambda'], ) = l.g_val(3)


class LSABE_AUTH(LSABE_MA): 
    def __init__(self, msk_path, max_kw, id):
        LSABE_MA.__init__(self, msk_path, max_kw)
        LSABE_MA.GlobalLoad(self)

        self._att_fname = msk_path.joinpath('authority-' + str(id) + '-lsabe-ma.att')   
        self._ask_fname = msk_path.joinpath('authority-' + str(id) + '-lsabe-ma.ask')
        self._apk_fname = msk_path.joinpath('authority-' + str(id) + '-lsabe-ma.apk')


# ................................................................................
# AuthoritySetup (PP)→(APK(i,j),ASK(i,j)). Each authority A(j) conducts the authority
# setup algorithm, which inputs public parameter PP and generates an attribute public  
# key APK(i,j) and an attribute secret key ASK(i,j) for each attributeithat it manages. 
# ................................................................................
# AuthoritySetup
# ................................................................................
    def AuthoritySetup(self, attrs):
        self._ATT = ()
        self._ASK = ()
        self._APK = ()
        for attr in attrs:
            ATTi = attr 
            a, y = random.randrange(sys.maxsize), random.randrange(sys.maxsize)
            beta = self.group.random(ZR)

            ASKi = {'a': random.randrange(sys.maxsize), 'y': random.randrange(sys.maxsize), 'beta': self.group.random(ZR) }

            APKi = { 'e(gg)^a' : pair(self._PP['g'], self._PP['g']) ** a, 'g**y': self._PP['g']**y, 'g**beta': self._PP['g']**beta }

            self._ATT = self._ATT + (ATTi, )
            self._ASK = self._ASK + (ASKi, )
            self._APK = self._APK + (APKi, )


        print("Authority secret key:")
        print(self._ASK)
        print("Authority public key:")
        print(self._APK)

        self.__serialize_A()


    def AuthorityLoad(self):
        self.__deserialize_A()


# ................................................................................
#  Authority serializer and deserializer
# ................................................................................

    def __serialize_A(self):
        att_f = SER(self._att_fname, self.group)
        ask_f = SER(self._ask_fname, self.group)
        apk_f = SER(self._apk_fname, self.group)

        sz = len(self._ATT)
        att_f.p_size(sz)
        ask_f.p_size(sz)
        apk_f.p_size(sz)

        for ATTi in self._ATT:
            att_f.p_bytes(b64encode(bytes(ATTi, 'utf-8')).decode('utf-8'))

        for ASKi in self._ASK:
            ask_f.p_bytes(b64encode(bytes(str(ASKi['a']), 'utf-8')).decode('utf-8')).p_bytes(b64encode(bytes(str(ASKi['y']), 'utf-8')).decode('utf-8')).p_val((ASKi['beta'], ))

        for APKi in self._APK:
            apk_f.p_val(APKi.values())


    def __deserialize_A(self):
        att_f = DES(self._att_fname, self.group)
        ask_f = DES(self._ask_fname, self.group)
        apk_f = DES(self._apk_fname, self.group)

        sz = att_f.g_size()
        sz = ask_f.g_size()
        sz = apk_f.g_size()

        self._ATT = ()
        self._ASK = ()
        self._APK = ()


        for i in range(sz):
            att_f.g_bytes()
            self._ATT = self._ATT + (b64decode(att_f.g_bytes()) ,)

            ASKi = {}
            ASKi['a'], ASKi['y'], ASKi['beta'] = ask_f.g_size(), ask_f.g_size(), ask_f.g_val(1)
            self._ASK = self._ASK + (ASKi, )
            
            APKi = {}
            APKi = apk_f.g_val(3)
            self._APK = self._APK + (APKi, )

        print("Authority secret key:")
        print(self._ASK)
        print("Authority public key:")
        print(self._APK)
