import os
import sys
import random
from pathlib import Path

from base64 import b64encode, b64decode

# https://jhuisi.github.io/charm/cryptographers.html
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair,extract_key

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
#  GlobalLoad
#  Deserializes MSK and PP from files
# ................................................................................
    def GlobalLoad(self):
        self.__deserialize_G()

#        print("Master secret key:")
#        print(self._MSK)
#        print("Public properties:")
#        print(self._PP)

# ................................................................................
#  Serializer and deserializer
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


