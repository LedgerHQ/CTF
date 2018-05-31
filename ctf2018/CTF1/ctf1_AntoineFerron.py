p = 1361
q = 6983
from fractions import gcd
n=p*q;print n
pm = p-1
qm = q-1
phi = pm*qm;print phi
res = 1
for e in xrange(3,phi,2):
	if gcd(e,phi)==1:
		if gcd(e-1,pm)*gcd(e-1,qm) == 4:
			res = (res*e)%1337694213377816
print res
