# .... LSABE helper functions ...

# .... Formule de Viete, seigneur de la Bigotiere ....
# Builds polynomial coefficients from its roots   
def formuleDeViete(roots):
      # Declare an array for  polynomial coefficient.
    n = len(roots)
    coeff = [0] * (n + 1)
      
    # Set Highest Order coefficient as 1
    coeff[n] = 1
    for i in range(1, n + 1):
        for j in range(n - i - 1, n):
            coeff[j] -= roots[i - 1] * coeff[j + 1]  
#  Note.  Charmcryptor ZR values do not really support negations but do support substractions.   
#         Canonical (-1) * (roots[i - 1] * coeff[j + 1]) breaks the calculation bitterly    
    
#   print("Polynomial Coefficients : ", end = "")
#    for i in coeff: 
#        print(i, end = " ")

    return coeff

# ... polyVal ...
# Calculates polynomial value for given x
# Used and/or reserverd for testing purposes only. May be commented or deleted out
def polyVal(coeff, x):
    val = 0
    xn = 1
    n = len(coeff)

    for i in range(0, n):
        val = val + coeff[i]*xn
        xn = xn * x

    return val
