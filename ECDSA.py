from EC import EC


class ECDSA():
    '''Reference: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm'''

    def __init__(self, curve, priv):
        self.curve = curve
        self.private = priv
        self.generator = self.curve.generator()
        self.public = self.curve.calc_public(self.generator, self.private)

    def sign(self, doc, rndm):
        curve_point = self.curve.multiply(self.generator, rndm)

        r = curve_point.x % self.curve.n    # if r is 0, choose another rndm
        s = self.curve.inv(rndm) * (doc + curve_point.x * self.private) % self.curve.n

        return [doc, (r, s)]

    def verify(self, doc, signature):

        assert self.curve.on_curve(self.public)
        assert self.curve.multiply(self.public, self.curve.n) == self.curve.inf

        r, s = signature
        assert r in range(1, self.curve.n) and s in range(1, self.curve.n)

        u1 = self.curve.inv(s) * doc % self.curve.n
        u2 = self.curve.inv(s) * r % self.curve.n

        curve_point = self.curve.point_addition(self.curve.multiply(self.generator, u1),
                                                self.curve.multiply(self.public, u2))

        if curve_point == self.curve.inf:
            return 'Invalid signature'
        if r == curve_point.x % self.curve.n:
            return "Valid Signature"
        else:
            return 'Invalid Signature'


ec = EC(1, 18, 19)
priv = 12
ec_sign = ECDSA(ec, priv)
doc = 123
rndm = 7  # select cryptographically secure random number
doc, signature = ec_sign.sign(doc, rndm)
print(doc, signature)
print(ec_sign.verify(doc, signature))
