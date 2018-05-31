import sys
import numpy as np
p = next_prime(1337) #p = 1361 
q = next_prime(6982) #q = 6983 

phi = (p-1)*(q-1)
prime_p2 = []
prime_p = []
prime_q = []
prime_q2 = []
suitable_e = []
for e in range(phi):
    if e % 100000 == 0:
        sys.stdout.write("{}            \r".format(e))
        sys.stdout.flush()
    gcd_p = gcd(p-1, e-1)
    gcd_q = gcd(q-1, e-1)
    if gcd_p == 1: 
        prime_p.append(e)
    if gcd_p == 2: 
        prime_p2.append(e)
    if gcd_q == 1: 
        prime_q.append(e)
    if gcd_q == 2: 
        prime_q2.append(e)
    if gcd(phi, e) == 1: 
        suitable_e.append(e)


print("\np={}".format(p))
print("q={}".format(q))

print("len(prime_p) = {}".format(len(prime_p)))
print("len(prime_p2) = {}".format(len(prime_p2)))
print("len(prime_q) = {}".format(len(prime_q)))
print("len(prime_q2) = {}\n".format(len(prime_q2)))


res = np.intersect1d(prime_p, prime_q)
res = np.intersect1d(res, suitable_e)

res1 = np.intersect1d(prime_p, prime_q2)
res1 = np.intersect1d(res1, suitable_e)

res2 = np.intersect1d(prime_p2, prime_q)
res2 = np.intersect1d(res2, suitable_e)

res3 = np.intersect1d(prime_p2, prime_q2)
res3 = np.intersect1d(res3, suitable_e)

print("len(res) = {}".format(len(res)))
print("len(res1) = {}".format(len(res1)))
print("len(res2) = {}".format(len(res2)))
print("len(res3) = {}".format(len(res3)))

true_res = 1
for i in res:
    sys.stdout.write("{}            \r".format(i))
    true_res *= i
    true_res = true_res % 1337694213377816

true_res1 = 1
for i in res1:
    sys.stdout.write("{}            \r".format(i))
    true_res1 *= i
    true_res1 = true_res1 % 1337694213377816

true_res2 = 1
for i in res2:
    sys.stdout.write("{}            \r".format(i))
    true_res2 *= i
    true_res2 = true_res2 % 1337694213377816

true_res3 = 1
for i in res3:
    sys.stdout.write("{}            \r".format(i))
    true_res3 *= i
    true_res3 = true_res3 % 1337694213377816

print("true result for (1,1) is: {}".format(true_res))
print("true result for (1,2) is: {}".format(true_res1))
print("true result for (2,1) is: {}".format(true_res2))
print("true result for (2,2) is: {}".format(true_res3))
