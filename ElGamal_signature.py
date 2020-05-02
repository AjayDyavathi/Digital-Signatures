import random


def xgcd(a, b):
    '''return (g, x, y) such that a*x + b*y = g = gcd(a, b)'''
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = xgcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    '''return x such that (x * a) % b == 1'''
    g, x, y = xgcd(a, m)
    if g != 1:
        raise Exception("Modular inverse doesn't exist: gcd(a, b) != 1")
    else:
        return x % m


def generate_prime_factors(n):
    i = 2
    prime_factors = []
    while i * i <= n:
        if n % i:
            i += 1
        else:
            n //= i
            if i not in prime_factors:
                prime_factors.append(i)
    if n > 1:
        prime_factors.append(n)
    return prime_factors


def find_primitive_root(p):
    '''returns a primitive_root-generator for given prime number p'''
    order = p - 1   # phi(p)

    if p == 2:
        return 1

    # consider a random number g from 2 to p-1
    # check if g**(order/x) mod p == 1 where x is iterated through all prime factors
    # if true then, g is not a generator, choose another g until it gets false

    prime_factors = generate_prime_factors(order)

    while True:
        g = random.randint(2, order)

        flag = False
        for factor in prime_factors:
            # pow -> pow(base, exponent, modulo)
            if pow(g, order // factor, p) == 1:
                flag = True
                break
        if flag:
            continue
        return g


class ElGamal_signature():

    def __init__(self, prime):
        self.prime = prime
        keys, self.gen = self.generate_keys()
        self.public, self.private = keys

    def generate_keys(self):
        '''generates public_key, private_key pair'''

        p = self.prime
        g = find_primitive_root(p)          # computing generator
        x = random.randint(1, p - 2)        # choosing private
        y = pow(g, x, p)                    # computing public

        self.private_key = x
        self.public_key = y
        return (self.public_key, self.private_key), g

    def sign(self, doc):

        # Choosing Ke(ephemeral_key) such that inverse exists
        k = random.randint(2, self.prime - 2)
        while xgcd(k, self.prime - 1)[0] != 1:
            k = random.randint(2, self.prime - 2)

        # Make sure gcd(k, prime) == 1, this is condition for coprimes, which
        # says that inverse exists for given number k in modulo prime
        assert xgcd(k, self.prime)[0] == 1

        r = pow(self.gen, k, self.prime)
        s = ((doc - (self.private * r)) * modinv(k, self.prime - 1)) % (self.prime - 1)
        return [doc, (r, s)]

    def verify(self, doc, signed_doc):

        r, s = signed_doc
        t = ((self.public**r) * (r**s)) % self.prime
        if t == pow(self.gen, doc, self.prime):
            return 'Valid Signature!'
        else:
            return 'Invalid Signature!'


elg_sign = ElGamal_signature(23)
doc = 123
doc, signed_doc = elg_sign.sign(doc)
print(f'doc: {doc}, singature: {signed_doc}')
print(elg_sign.verify(doc, signed_doc))
