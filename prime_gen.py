from sympy import isprime

logN = 16
start = (1 << 44) + 1
walk = +(1 << (logN + 1))
numprime = 1
res = []

crr = start
while (len(res) < numprime):
    crr += walk
    if (isprime(crr)):
        res.append(crr)
        if (len(res) % 4 == 0):
            print(hex(crr) + ",")
        else:
            print(hex(crr) + ",", end=" ")
