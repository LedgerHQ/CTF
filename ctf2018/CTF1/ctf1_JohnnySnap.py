#!/usr/bin/env python

import gmpy2

def solve(p, q):
    phi = (p - 1) * (q - 1)
    result = 1
    for e in range(2, phi):
        if gmpy2.gcd(e, phi) != 1:
            continue

        a = (1 + gmpy2.gcd(e - 1, p - 1)) * (1 + gmpy2.gcd(e - 1, q - 1))
        if a == 9:
            result = (result * e) % 1337694213377816

    return result

p = gmpy2.next_prime(1337)
q = gmpy2.next_prime(6982)
result = solve(p, q)

print 'ctf2018+%d@ledger.fr' % result
