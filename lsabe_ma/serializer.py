# .... LSABE helper classes ...
# SER - serializer  
# DES - deserializer 

from base64 import b64encode, b64decode
import re

# .... SER - serializer .... 
class SER():
    def __init__(self, f, group, open = True):
        # f is either a file name (open = True) 
        #    or
        # BytesIO object (open = False)
        if open:
            self.__file =f.open(mode='wb')
            self.__c = True
        else:
            self.__file = f
            self.__c = False
        self.__g = group

    def __del__(self):
        if self.__c:
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

    def p_size(self, sz):
        self.__file.write(b'%(len)04d' %{b"len":  sz} )
        self.__file.write(b' ')
        return self

    def p_int(self, val):
        self.p_bytes(b64encode(bytes(str(val), 'utf-8')).decode('utf-8'))
        return self

    def p_str(self, s):
        self.p_bytes(b64encode(bytes(s, 'utf-8')).decode('utf-8'))
        return self

# .... DES - deserializer ...
class DES():
    def __init__(self, f, group, open = True):
        # f is either a file name (open = True) 
        #    or
        # Byte buffer (open = False)
        if open:
            file =f.open(mode='rb')
            data = file.read().decode('utf-8')
            file.close
        else:
            data = f.decode('utf-8')
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

    def g_size(self):
        sz = int(self.__d[self.__i])
        self.__i = self.__i + 1
        return sz

    def g_int(self):
        val = int(b64decode(self.__d[self.__i]).decode('utf-8'))
        self.__i = self.__i + 1
        return val

    def g_str(self):
        s = b64decode(self.__d[self.__i]).decode('utf-8')
        self.__i = self.__i + 1
        return s
