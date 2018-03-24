#生成密钥
def generateKey(keySize):
    p = rabinMiller.generateLargePrime(keySize)#创建p,q,n
    q = rabinMiller.generateLargePrime(keySize)
    n = p * q
    while True:
        e = random.randrange(2 ** (keySize - 1), 2 ** (keySize))#创建e
        if cryptomath.gcd(e, (p - 1) * (q - 1)) == 1:
            break
    d = cryptomath.findModInverse(e, (p - 1) * (q - 1)) #计算d
    publicKey = (n, e)
    privateKey = (n, d)
    return (publicKey, privateKey)
	

