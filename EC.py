from collections import namedtuple
import random

point = namedtuple('point', ['x', 'y'])


class EC():
    '''Elliptic Curve'''

    def __init__(self, a, b, n):

        assert 0 < a < n and 0 < b < n and n > 2, 'parameters does not meet requirement'
        assert (4 * (a**3) + 27 * (b**2)) % n != 0, 'wrong curve'
        self.a = a
        self.b = b
        self.n = n
        self.inf = (0, 0)

    def on_curve(self, p):
        '''verifys if the point lie on the curve'''

        if p == self.inf:
            return True

        status = (p.y**2) % self.n == (p.x**3 + self.a * p.x + self.b) % self.n
        return status

    def generator(self):
        ''' returns a random generator from a list of generators for the curve'''
        perfect_squares = {}
        base = 1
        while True:
            perfect_square = pow(base, 2, self.n)
            if perfect_square in perfect_squares:
                break
            perfect_squares[perfect_square] = base
            base += 1

        generators = []
        for x in range(base):
            y_square = ((x**3) + self.a * x + self.b) % self.n
            if y_square in perfect_squares:
                pt1 = point(x, perfect_squares[y_square])
                pt2 = point(x, -perfect_squares[y_square] % self.n)
                generators.append(pt1)
                generators.append(pt2)
        # print(generators)

        # verify all the generators lie on the curve
        assert all(list(map(self.on_curve, generators)))
        return random.choice(generators)

    def xgcd(self, a, b):
        '''return (g, x, y) such that a*x + b*y = g = gcd(a, b)'''
        s0, s1, t0, t1 = 1, 0, 0, 1
        while b > 0:
            q, r = divmod(a, b)
            a, b = b, r
            s0, s1, t0, t1 = s1, s0 - q * s1, t1, t0 - q * t1
        return a, s0, t0

    def inv(self, a):
        '''return x such that (x * a) % self.n == 1'''
        g, x, y = self.xgcd(a, self.n)
        return x % self.n

    def point_addition(self, p, q):
        '''point addition of 2 points'''
        if p == self.inf:
            return q

        elif q == self.inf:
            return p

        elif p.x == q.x and p.y != q.y:
            return self.inf

        if p.x == q.x:
            s = ((3 * (p.x**2) + self.a) * self.inv(2 * p.y)) % self.n
        else:
            s = ((q.y - p.y) * self.inv(q.x - p.x)) % self.n

        x_coordinate = ((s * s) - p.x - q.x) % self.n
        y_coordinate = (s * (p.x - x_coordinate) - p.y) % self.n

        result = point(x_coordinate, y_coordinate)
        assert self.on_curve(result), f'failed with {p}, {q} = {result} and s:{s}'

        return result

    def multiply(self, p, n):
        '''Multiplies the point p for n times'''
        result = self.inf
        pt = p
        while n > 0:
            if n & 1 == 1:
                result = self.point_addition(result, pt)
            n, pt = n >> 1, self.point_addition(pt, pt)

        assert self.on_curve(result)
        return result

    def calc_public(self, gen, private):
        '''Calculate public_point from private number'''
        return self.multiply(gen, private)
