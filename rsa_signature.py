import random


def isprime(num):
    '''check if num is prime'''
    if num < 2:
        return False
    if num == 2 or num == 3:
        return True
    if num % 2 == 0:
        return False
    for i in range(3, int(num**.5) + 1, 2):
        if num % i == 0:
            return False
    return True


def xgcd(a, b):
    '''return (gcd, x, y) such that a*x + b*y = g = gcd(a, b)'''
    if a == 0:
        return b, 0, 1
    else:
        gcd, y, x = xgcd(b % a, a)
        return (gcd, x - (b // a) * y, y)


def modinv(a, n):
    '''return inverse modulo n
    which returns x where (x * a) mod n == 1'''

    g, x, y = xgcd(a, n)
    if g != 1:
        raise Exception('Cant find inverse')
    else:
        return x % n


class RSA_Signature():
    '''RSA Signature Class, public keys are automatically chosen
    and private keys are automatically computed with the initialisation
    of object.
    Note: Choose primes greater than 7 and make sure they're distinct'''

    def __init__(self, prime1, prime2):

        self.p = prime1
        self.q = prime2
        self.pub_keys, self.priv_keys = self.generate_keypair()

    def generate_keypair(self):
        '''returns public key based on private key'''
        self.n = self.p * self.q
        phi = (self.p - 1) * (self.q - 1)

        # Choose public shich that gcd(pub, phi) == 1
        # which indicates chose public has inverse
        self.public = random.randint(2, phi - 1)
        while xgcd(self.public, phi)[0] != 1:
            self.public = random.randint(2, phi - 1)

        assert xgcd(self.public, phi)[0] == 1

        self.private = modinv(self.public, phi)
        return (self.public, self.n), (self.private, self.n)

    def sign(self, message):
        '''Signs the message with private key'''
        signature = pow(message, self.private, self.n)
        return signature

    def verify(self, message, signed_message):
        '''Verifys the message with signed message by using owner's
        public key, usually done at other parties'''
        return message == pow(signed_message, self.public, self.n)


rsa_sign = RSA_Signature(23, 17)
doc = 123
print(f'Public key:{rsa_sign.pub_keys}, Private key: {rsa_sign.priv_keys}')

# Signing the document
sign = rsa_sign.sign(doc)

# Verification of Signature
if rsa_sign.verify(doc, sign):
    print('Signature valid!')
else:
    print('Signature Invalid!')
