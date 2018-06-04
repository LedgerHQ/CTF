#!/usr/bin/python2
# -*- coding: ascii -*-

# Ledger Capture The Flag 2018 Challenge 1
# Copyright (C) 2018  Antoine FERRON - BitLogiK


from fractions import gcd

p, q = 1361, 6983
modulo = 1337694213377816
n=p*q;print "n = ",n
pm, qm, = p-1, q-1
phi = pm*qm
res = 1
for e in xrange(3,phi,2):
	if gcd(e-1,pm)==2 and gcd(e-1,qm)==2:
		if gcd(e,phi)==1:
			res = (res*e)%modulo
print res
