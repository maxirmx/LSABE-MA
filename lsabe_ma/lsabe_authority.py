import os
import sys
import random
from pathlib import Path

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

    @property
    def att_fname(self):
        return str(self._att_fname)

    @property
    def ask_fname(self):
        return str(self._ask_fname)

    @property
    def apk_fname(self):
        return str(self._apk_fname)

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
            alfa, y = random.randrange(sys.maxsize), random.randrange(sys.maxsize)
            beta = self.group.random(ZR)
            ASKi = {'alfa': alfa, 'y': y, 'beta': beta }
            APKi = { 'e(gg)^alfa' : pair(self._PP['g'], self._PP['g']) ** alfa, 'g**y': self._PP['g']**y, 'g**beta': self._PP['g']**beta }

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
            att_f.p_str(ATTi)

        for ASKi in self._ASK:
            ask_f.p_int(ASKi['alfa']).p_int(ASKi['y']).p_val((ASKi['beta'], ))

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
            self._ATT = self._ATT + (att_f.g_str(), ) 
            self._ASK = self._ASK + ({'alfa': ask_f.g_int(), 'y': ask_f.g_int(), 'beta': ask_f.g_val(1)[0]}, )          
            APKi = {}
            APKi['e(gg)^alfa'], APKi['g**y'], APKi['g**beta'] = apk_f.g_val(3)  
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

# The aricles says H: {0,1}* --> G, i.e.: hGID = self.group.hash(GID, G1)
# However, it won't work since T4 = H(HID) and I0^T4 is used in Search operation
# I believe that  power is not defined on GxG. 
# Anyway H: {0,1}* --> ZR* does not make anythging worse
        hGID = self.group.hash(GID, ZR)
        HGID = self.group.hash(GID, G1)

        SK = ()
 
        for s in range(len(self._ATT)):
            for a2 in attrs:
                if self._ATT[s]==a2:
#   The article says K1 = g^(alfa/(lambda+delta)), but it makes no sense since delta is not defined
#   It looks like copy-paste from LSABE 
#   Algorith works if K1 = g^(alfa/(lambda + H(GID))) -- both if formula is checked and implemented in sw                 
                    K1 = self._PP['g'] ** (self._ASK[s]['alfa']/(self._MSK['lambda'] + hGID))
                    K3 = HGID ** self._ASK[s]['y']
                    K4 = (self._PP['g'] ** self._ASK[s]['alfa']) * (HGID ** self._ASK[s]['beta'])
                    SKs = (K1, K3, K4)
#                    print("Secret key [" + a2 + "]:")
#                    print(K1, K3, K4)
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
#            print(SKs)
        return SK 

# ................................................................................
# TransKeyGen({SKi,GID},z) → TKGID. 
# Data user runs the TransKeyGen algorithm, which takes as input the secret keyset  
# and  a  blind  valuez,  and  outputs  the  transformation  keyTKGID. 
# ................................................................................
    
    def TransKeyGen(self, SK, z, GID):
        TK2 = self.group.hash(GID, G1) ** z
        TK3 = ()
        TK4 = ()
        for SKs in SK:
            (K1, K3, K4) = SKs  
            TK3 = TK3 + (K3 ** z, )
            TK4 = TK4 + (K4 ** z, ) 

#        print ("Transformation key:")
#        print ((TK2, TK3, TK4))

        return (TK2, TK3, TK4)

# ................................................................................
#  TK serializer and deserializer
# ................................................................................
    def serialize__TK(self, TK, tk_fname, open = True):
        (TK2, TK3, TK4) = TK
        l = SER(tk_fname, self.group, open)
        l.p_val((TK2, ))
        sz = len(TK3)
        l.p_size(sz)
        for i in range(sz):
            l.p_val((TK3[i],TK4[i]))

    def deserialize__TK(self, sk_fname, open = True):
        l = DES(sk_fname, self.group, open)
        TK2 = l.g_val(1)[0]
        TK3 = ()
        TK4 = ()
        sz = l.g_size()
        for i in range(sz):
            (TK3i, TK4i) = l.g_val(2)
            TK3 = TK3 + (TK3i, )
            TK4 = TK4 + (TK4i, )
#        print((TK2, TK3, TK4))
        return (TK2, TK3, TK4)

# ................................................................................
# Encrypt  (M,(A,ρ),KW,PP,{APK(i,j)}) → CT.  
# Given  file M, access policy(A,ρ), keyword set KW, PP and theset of attribute public 
# keys APK(i,j) for  relevant  authorities, the Encrypt outputs  the  ciphertext CT,  
# which  contains the encrypted secure index I and the encrypted file CM.
# ................................................................................
    def EncryptAndIndexGen(self, M, KW):

        UpsilonWithHook = self.group.random(GT)
        kse = extract_key(UpsilonWithHook)

        a   = SymmetricCryptoAbstraction(kse)
        CM = a.lsabe_encrypt(bytes(M, "utf-8"))

        hkw = []
        for kw in KW:
            hkw.append(self.group.hash(kw, ZR))
        
        eta = formuleDeViete(hkw)

# Formule de Viete assumes P(x)=0
# We have P(x)=1, so eta[0] is adjusted
        eta[0] = eta[0] + 1

# .....
# Check that polynomial coefficients are correct
#        for hkwi in hkw:
#            print ('P(' + str(hkwi) + ') = ' + str(polyVal(eta, hkwi)) + ' ~~~~ expected 1')

        rho1, b = self.group.random(ZR), self.group.random(ZR)

        v = self._ap.randVector()
        s = v[0]
        g = self._PP['g']

        I0 = g ** b
        I1 = g ** (self._MSK['lambda']*b)
        I2 = g ** s
        I3 = g ** rho1  
        I  = ()
        I4 = ()
        E2 = ()
        for i in range(len(self._ATT)):
            ASKpi = self._ASK[self._ap.p(i)]
            APKpi = self._APK[self._ap.p(i)]
            Ii = UpsilonWithHook * ( ( APKpi['e(gg)^alfa'] )**s ) 
            I4i = ( g **(ASKpi['beta'] * self._ap.lmbda(i,v)) ) * ( g ** (rho1 * ASKpi['y'])) 
#                                                                The article says:  ** -rho1          
#                                                                but it is definetely a mistake 
            E2i = (APKpi['e(gg)^alfa'])**(b*rho1)

            I  = I  + (Ii, )
            I4 = I4 + (I4i, )
            E2 = E2 + (E2i, )
        
        E1 = pair(self._PP['g'], self._PP['f']) ** rho1

        I5 = ( )
        for eta_j in eta:
            I5 = I5 + ((rho1 ** (-1)) * eta_j,  )

#        print("Ciphertext: ")
#        print((I, I0, I1, I2, I3, I4, I5, E1, E2, CM))

        return (I, I0, I1, I2, I3, I4, I5, E1, E2, CM)

# ................................................................................
#  Ciphertext serializer and deserializer
# ................................................................................
    def serialize__CT(self, CT, ct_fname, open=True):
        (I, I0, I1, I2, I3, I4, I5, E1, E2, CM) = CT
        (ctCT, ctIV) = CM

        l = SER(ct_fname, self.group, open)
        l.p_tup(I).p_val((I0, I1, I2, I3)).p_tup(I4).p_tup(I5).p_val((E1,)).p_tup(E2).p_bytes(ctCT).p_bytes(ctIV)

    def deserialize__CT(self, ct_fname, open=True):
        l = DES(ct_fname, self.group, open)
        return ((l.g_tup(), ) + l.g_val(4) + (l.g_tup(), ) + (l.g_tup(), ) + l.g_val(1) + (l.g_tup(), ) + ((l.g_bytes(), ) + (l.g_bytes(), ) ,) )

# ................................................................................
# Trapdoor ({SKi,GID},KW′,PP)→TKW′. 
# Given the secret key set, query keyword set KW′ and PP, data users run Trapdoor, 
# which outputs the keyword trapdoor TKW′.
# ................................................................................

    def TrapdoorGen(self, SK, GID, KW):
        u, rho2 = self.group.random(ZR), self.group.random(ZR)

        T1 = ()
        for sk in SK:
            (K1, K3, K4) = sk
            T1sk = K1 ** u
            T1 = T1 + (T1sk, )

        T2 = self.group.hash(GID, ZR)
        lKW = self._1 * len(KW)                     # Make it ZR* value otherwise lkW**(-1) makes little sense 
        T3 = (u * rho2) * (lKW**(-1))

        T4 = ( )
        for j in range(0, self._max_kw):
            T4j = 0
            for kw in KW:
                T4j = T4j + self.group.hash(kw, ZR) ** j
            T4 = T4 + ((rho2 ** (-1)) * T4j ,)

        T5 = pair(self._PP['g'], self._PP['f']) ** u

#        print ("Trapdoor:")
#        print ((T1, T2, T3, T4, T5))

        return (T1, T2, T3, T4, T5)

# ................................................................................
#  Trapdoor serializer and deserializer
# ................................................................................
    def serialize__TD(self, TD, td_fname, open = True):
        (T1, T2, T3, T4, T5) = TD

        l = SER(td_fname, self.group, open)
        l.p_tup(T1).p_val((T2, T3)).p_tup(T4).p_val((T5,))

    def deserialize__TD(self, td_fname, open = True):
        l = DES(td_fname, self.group, open)
        return ((l.g_tup(), ) + l.g_val(2) + (l.g_tup(), ) + l.g_val(1))

# ................................................................................
# Search(CT,TKW′) → 0/1.  
# The cloud server takes the trap-door TKW′ and the ciphertext CT as input, 
# and executes the search algorithm. If the output is “0”, the  query  fails.  
# If theoutput is “1”, the query is successful and the cloud servers continue 
# to run the transform algorithm.
# ................................................................................
    def Search(self, CT, TKW):
        (I, I0, I1, I2, I3, I4, I5, E1, E2, CM) = CT
        (T1, T2, T3, T4, T5) = TKW

        T1m = T1[self._ap.p(0)]
        E2m = E2[0]
        for i in range(1, len(T1)):
            T1m = T1m * T1[self._ap.p(i)]
            E2m = E2m * E2[i]

        T4m = I5[0]*T4[0]
        for j in range(1, len(I5)):
            T4m = T4m + I5[j]*T4[j]

        return (T5 * pair(T1m, (I0 ** T2) * I1) == (E1 * E2m) ** (T3 * T4m))

# ................................................................................
# Transform (CT,TKGID) → CTout/⊥.  
# Given the transformation key TKGID, the cloud server can transform the ciphertext  
# into a transformed ciphertext and then returns the transformed ciphertext CTout 
# to the user end. Otherwise, itoutputs ⊥.
# ................................................................................
    def Transform(self, CT, TK):
        (I, I0, I1, I2, I3, I4, I5, E1, E2, CM)   = CT
        (TK2, TK3, TK4) = TK

        N = len(TK4)

        TK3m  = self._1
        TK4m  = self._1
        I4m   = self._1
        Im    = self._1

        for i in range (N):
            I4m  = I4m * (I4[i] ** self._ap.w(i))
            TK3m = TK3m * (TK3[self._ap.p(i)] ** self._ap.w(i))
            TK4m = TK4m * TK4[self._ap.p(i)]
            Im   = Im * I[i]

        TI = pair(TK4m, I2) / pair(I4m, TK2) * pair(I3, TK3m)
        TTI = Im

        return (CM,TI,TTI,N)    


# ................................................................................
#  Partially decrypted ciphertext serializer and deserializer
# ................................................................................
    def serialize__CTout(self, CTout, ct_fname, open = True):
        (CM, TI, TTI, N) = CTout
        (ctCT, ctIV) = CM

        l = SER(ct_fname, self.group, open)
        l.p_val((TI, TTI)).p_bytes(ctCT).p_bytes(ctIV).p_int(N)

    def deserialize__CTout(self, ct_fname, open = True):
        l = DES(ct_fname, self.group, open)
        (TI, TTI) = l.g_val(2)
        ctCT = l.g_bytes()
        ctIV = l.g_bytes()
        N = l.g_int()
        CM = (ctCT, ctIV)
        return (CM, TI, TTI, N)


# ................................................................................
#  Decrypt(z,CTout) → M.  
#  The data user runs the Decrypt algorithm with its blind value z and the partially 
#  decrypted ciphertext CT out as input, and then the user can recover the message 
#  M with lightweight decryption
# ................................................................................

    def Decrypt(self, z, CTout):

        (CM,TI,TTI,N) = CTout

        UpsilonWithHook = (TTI/(TI**(self._1/z)))**(self._1/N)
        kse = extract_key(UpsilonWithHook)
        a   = SymmetricCryptoAbstraction(kse)
        M   = a.lsabe_decrypt(CM)

        return M
