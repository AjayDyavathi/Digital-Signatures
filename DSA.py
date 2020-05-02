import random


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


class DSA():
    ''' 
    Digital Signature Algorithm
    >>> m = message
    >>> H = hash(m)
    >>> N = mod_length
    >>> if len(H) > N: H = H[:N]
    >>> L = key_length
    # choose mod_length N, such that N < L and N <= len(H)
    # usually (L, N) is from [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]
    # choose N-bit prime, q
    # choose L-bit prime, p. such that (p-1) is multiple of q
    # gcd(q, p) != 1
    '''

    def __init__(self, q, p):
        self.q = q
        self.p = p
        self.h = random.randint(2, p - 1)
        self.g = pow(self.h, (self.p - 1) // q, self.p)

    def calc_public(self, private):
        '''Compute public key'''
        assert 1 <= private <= self.q - 1

        y = pow(self.g, private, self.p)
        return y

    def sign(self, doc, private):
        '''Signs a document on signer's side '''

        # choose a temporary key
        k = random.randint(1, self.q)
        while xgcd(k, self.q)[0] != 1:
            k = random.randint(1, self.q)

        r = pow(self.g, k, self.p) % self.q
        s = (modinv(k, self.q) * (doc + (private * r))) % self.q

        return [doc, (r, s)]

    def verify(self, doc, signature, public):
        '''Verifys the document aganist signature provided public key'''

        r, s = signature
        assert 0 < r < self.q
        assert 0 < s < self.q

        w = modinv(s, self.q) % self.q
        u1 = (doc * w) % self.q
        u2 = (r * w) % self.q

        v = ((self.g**u1) * (public**u2)) % self.q
        if r == v:
            return 'Valid Signature!'
        else:
            return 'Invalid Signature!'


dss_sign = DSA(7, 3)    # initialise DSA object
priv = 5                # choose private in range {1, 2, ... , q-1}

pub = dss_sign.calc_public(priv)
doc = 123               # usually doc should be hashed value of a document

doc, signature = dss_sign.sign(doc, priv)   # signing a document at signer's side
print(dss_sign.verify(doc, signature, pub))  # validating signature
