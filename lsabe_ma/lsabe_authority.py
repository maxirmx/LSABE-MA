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

from .lsabe_ma import LSABE_MA

# ................................................................................
# LSABE-MA Authority

class LSABE_AUTH(LSABE_MA): 
    def __init__(self, msk_path, max_kw, id):
        LSABE_MA.__init__(self, msk_path, max_kw)
        LSABE_MA.GlobalLoad(self)

        self._att_fname = msk_path.joinpath('authority-' + str(id) + '.att')   
        self._ask_fname = msk_path.joinpath('authority-' + str(id) + '.ask')
        self._apk_fname = msk_path.joinpath('authority-' + str(id) + '.apk')

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

            ASKi = {'alfa': random.randrange(sys.maxsize), 'y': random.randrange(sys.maxsize), 'beta': self.group.random(ZR) }

            APKi = { 'e(gg)^a' : pair(self._PP['g'], self._PP['g']) ** a, 'g**y': self._PP['g']**y, 'g**beta': self._PP['g']**beta }

            self._ATT = self._ATT + (ATTi, )
            self._ASK = self._ASK + (ASKi, )
            self._APK = self._APK + (APKi, )

#        print("Authority attributes:")
#        print(self._ATT)
#        print("Authority secret key:")
#        print(self._ASK)
#        print("Authority public key:")
#        print(self._APK)

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
            ask_f.p_bytes(b64encode(bytes(str(ASKi['alfa']), 'utf-8')).decode('utf-8')).p_bytes(b64encode(bytes(str(ASKi['y']), 'utf-8')).decode('utf-8')).p_val((ASKi['beta'], ))

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
            self._ATT = self._ATT + (b64decode(att_f.g_bytes()).decode('utf-8'), ) 

            a = b64decode(ask_f.g_bytes()).decode('utf-8')
            y = b64decode(ask_f.g_bytes()).decode('utf-8')

            ASKi = {'alfa': int(a), 'y': int(y), 'beta': ask_f.g_val(1)[0]}
            self._ASK = self._ASK + (ASKi, )
            
            APKi = {}
            APKi['e(gg)^a'], APKi['g**y'], APKi['g**beta'] = apk_f.g_val(3)  
            self._APK = self._APK + (APKi, )

#        print("Authority attributes:")
#        print(self._ATT)
#        print("Authority public key:")
#        print(self._APK)
#        print("Authority secret key:")
#        print(self._ASK)
#        print("Authority public key:")
#        print(self._APK)

# ................................................................................
# SecretKeyGen(MSK,i,PP,GID,ASK(i,j))→SK(i,GID). 
# Given PP,GID, an attribute i belonging to a certain authority, and the attribute 
# secret key ASK(i,j) for this authority. The SecretkeyGen algorithm generates 
# a secret key SK(i,GID) for this attribute and sends it to the data user.
# ................................................................................
    def SecretKeyGen(self, GID, attrs):

        delta = self.group.random(ZR)
        hGID = self.group.hash(GID, G1)

        SK = ()

        for s in range(len(self._ATT)):
            for a2 in attrs:
                if self._ATT[s]==a2:
                    t = self.group.random(ZR)
                    K1 = self._PP['g'] ** (self._ASK[s]['alfa']/(self._MSK['lambda'] + delta))
                    K3 = hGID ** self._ASK[s]['y']
                    K4 = (self._PP['g'] ** self._ASK[s]['alfa']) * (hGID ** self._ASK[s]['beta'])
                    SKs = (K1, K3, K4)
                    print("Secret key [" + a2 + "]:")
                    print(K1, K3, K4)
                    SK = SK + (SKs, )

        return SK 

# ................................................................................
#  SK serializer and deserializer
# ................................................................................
    def serialize__SK(self, SK, sk_fname):
        l = SER(sk_fname, self.group)
        sz = len(SK)
        l.p_size(sz)
        for SKs in SK:
            (K1, K3, K4) = SKs
            l.p_val((K1,K3,K4))

    def deserialize__SK(self, sk_fname):
        SK = ()
        l = DES(sk_fname, self.group)
        sz = l.g_size()
        for s in range(sz):
            SKs = l.g_val(3)
            SK = SK + (SKs, )
            print(SKs)
        return SK 
