# .... LSABE helper classes ...
# SER - serializer  
# DES - deserializer 


import re

# .... SER - serializer .... 
class SER():
    def __init__(self, fname, group):
        self.__file =fname.open(mode='wb')
        self.__g = group

    def __del__(self):
        self.__file.close()

    def p_val(self, R):
        for v in R:
            self.__file.write(self.__g.serialize(v))
            self.__file.write(b' ')
        return self

    def p_tup(self, R):
        self.__file.write(b'%(len)04d' %{b"len":  len(R)} )
        self.__file.write(b' ')
        self.p_val(R)
        return self

    def p_bytes(self, M):
        self.__file.write(bytes(M, "utf-8"))
        self.__file.write(b' ')
        return self

# .... DES - deserializer ...
class DES():
    def __init__(self, fname, group):
        file =fname.open(mode='rb')
        data = file.read().decode('utf-8')
        file.close
        self.__d = data.split()
        self.__i = 0
        self.__g = group

    def g_val(self, n):
        R = ()
        for i in range(0, n):     
            R = R +(self.__g.deserialize(self.__d[self.__i].encode()),)
            self.__i = self.__i + 1
        return R

    def g_tup(self):
        sz = int(self.__d[self.__i])
        self.__i = self.__i + 1
        return self.g_val(sz)

    def g_bytes(self):
        self.__i = self.__i + 1
        return self.__d[self.__i - 1]
