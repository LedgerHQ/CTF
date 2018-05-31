#!/usr/bin/env python

# the code below is 'borrowed' almost verbatim from electrum,
# https://gitorious.org/electrum/electrum
# and is under the GPLv3.

# Modified for Ledger CTF by Guena


import ecdsa
import base64
import hashlib
from ecdsa.util import string_to_number
import sys

VERBOSE = False
#VERBOSE = True

# secp256k1, http://www.oid-info.com/get/1.3.132.0.10
_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L
curve_secp256k1 = ecdsa.ellipticcurve.CurveFp( _p, _a, _b )
generator_secp256k1 = ecdsa.ellipticcurve.Point( curve_secp256k1, _Gx, _Gy, _r )
oid_secp256k1 = (1,3,132,0,10)
SECP256k1 = ecdsa.curves.Curve("SECP256k1", curve_secp256k1, generator_secp256k1, oid_secp256k1 ) 

addrtype = 0

# from http://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python/

def modular_sqrt(a, p):
    """ Find a quadratic residue (mod p) of 'a'. p
    must be an odd prime.
    
    Solve the congruence of the form:
    x^2 = a (mod p)
    And returns x. Note that p - x is also a root.
    
    0 is returned is no square root exists for
    these a and p.
    
    The Tonelli-Shanks algorithm is used (except
    for some simple cases in which the solution
    is known from an identity). This algorithm
    runs in polynomial time (unless the
    generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) / 4, p)
    
    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s /= 2
        e += 1
        
    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1
        
    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #
    
    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) / 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e
    
    while True:
        t = b
        m = 0
        for m in xrange(r):
            if t == 1:
                break
            t = pow(t, 2, p)
            
        if m == 0:
            return x
        
        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m
        
def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
    Euler's criterion. p is a prime, a is
    relatively prime to p (if p divides
    a, then a|p = 0)
    
    Returns 1 if a has a square root modulo
    p, -1 otherwise.
    """
    ls = pow(a, (p - 1) / 2, p)
    return -1 if ls == p - 1 else ls

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
    """ encode v, which is a string of bytes, to base58.
    """

    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * ord(c)

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == '\0': nPad += 1
        else: break

    return (__b58chars[0]*nPad) + result

def b58decode(v, length):
    """ decode v into a string of len bytes."""
    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base**i)
    
    result = ''
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result
    
    nPad = 0
    for c in v:
        if c == __b58chars[0]: nPad += 1
        else: break
    
    result = chr(0)*nPad + result
    if length is not None and len(result) != length:
        return None
    
    return result

def msg_magic(message):
    return message
    #return "\x18Bitcoin Signed Message:\n" + chr( len(message) ) + message

def Hash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def hash_160(public_key):
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(public_key).digest())
    return md.digest()

def hash_160_to_bc_address(h160):
    vh160 = chr(addrtype) + h160
    h = Hash(vh160)
    addr = vh160 + h[0:4]
    return b58encode(addr)

def public_key_to_bc_address(public_key):
    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160)

def encode_point(pubkey, compressed=False):
    order = generator_secp256k1.order()
    p = pubkey.pubkey.point
    x_str = ecdsa.util.number_to_string(p.x(), order)
    y_str = ecdsa.util.number_to_string(p.y(), order)
    if compressed:
        return chr(2 + (p.y() & 1)) + x_str
    else:
        return chr(4) + x_str + y_str

def sign_message(private_key, message, compressed=False):
    public_key = private_key.get_verifying_key()
    signature = private_key.sign_digest( Hash( msg_magic( message ) ), sigencode = ecdsa.util.sigencode_string )
    address = public_key_to_bc_address(encode_point(public_key, compressed))
    assert public_key.verify_digest( signature, Hash( msg_magic( message ) ), sigdecode = ecdsa.util.sigdecode_string)
    for i in range(4):
        nV = 27 + i
        if compressed:
            nV += 4
        sig = base64.b64encode( chr(nV) + signature )
        try:
            if verify_message( address, sig, message):
                return sig
        except:
            continue
    else:
        raise BaseException("error: cannot sign message")

def verify_message(address, signature, message):
    """ See http://www.secg.org/download/aid-780/sec1-v2.pdf for the math """
    from ecdsa import numbertheory, ellipticcurve, util
    curve = curve_secp256k1
    G = generator_secp256k1
    order = G.order()
    # extract r,s from signature
    sig = base64.b64decode(signature)
    if len(sig) != 65: raise BaseException("Wrong encoding")
    r,s = util.sigdecode_string(sig[1:], order)
    nV = ord(sig[0])
    if nV < 27 or nV >= 35:
        return False
    if nV >= 31:
        compressed = True
        nV -= 4
    else:
        compressed = False
    recid = nV - 27
    # 1.1
    x = r + (recid/2) * order
    # 1.3
    alpha = ( x * x * x  + curve.a() * x + curve.b() ) % curve.p()
    beta = modular_sqrt(alpha, curve.p())
    y = beta if (beta - recid) % 2 == 0 else curve.p() - beta
    # 1.4 the constructor checks that nR is at infinity
    R = ellipticcurve.Point(curve, x, y, order)
    # 1.5 compute e from message:
    h = Hash( msg_magic( message ) )
    e = string_to_number(h)
    minus_e = -e % order
    # 1.6 compute Q = r^-1 (sR - eG)
    inv_r = numbertheory.inverse_mod(r,order)
    Q = inv_r * ( s * R + minus_e * G )
    public_key = ecdsa.VerifyingKey.from_public_point( Q, curve = SECP256k1 )
    # check that Q is the public key
    public_key.verify_digest( sig[1:], h, sigdecode = ecdsa.util.sigdecode_string)
    # check that we get the original signing address
    addr = public_key_to_bc_address(encode_point(public_key, compressed))
    if address == addr:
        return True
    else:
        #print addr
        return False


def sign_message_with_secret(secret, message, nounce, compressed=False):
    private_key = ecdsa.SigningKey.from_secret_exponent( secret, curve = SECP256k1 )
    
    public_key = private_key.get_verifying_key()
    signature = private_key.sign_digest( Hash( msg_magic( message ) ), sigencode = ecdsa.util.sigencode_string, k=nounce )
    address = public_key_to_bc_address(encode_point(public_key, compressed))
    if VERBOSE: print 'address:\n', address
    assert public_key.verify_digest( signature, Hash( msg_magic( message ) ), sigdecode = ecdsa.util.sigdecode_string)
    for i in range(4):
        nV = 27 + i
        if compressed:
            nV += 4
        sig = base64.b64encode( chr(nV) + signature )
        try:
            if verify_message( address, sig, message):
                return sig
        except:
            continue
    else:
        raise BaseException("error: cannot sign message")


def sign_message_with_private_key(base58_priv_key, message, nounce, compressed=True):
    encoded_priv_key_bytes = b58decode(base58_priv_key, None)
    encoded_priv_key_hex_string = encoded_priv_key_bytes.encode('hex')
    
    secret_hex_string = ''
    if base58_priv_key[0] == 'L' or base58_priv_key[0] == 'K':
        assert len(encoded_priv_key_hex_string) == 76
        # strip leading 0x08, 0x01 compressed flag, checksum
        secret_hex_string = encoded_priv_key_hex_string[2:-10]
    elif base58_priv_key[0] == '5':
        assert len(encoded_priv_key_hex_string) == 74
        # strip leading 0x08 and checksum
        secret_hex_string = encoded_priv_key_hex_string[2:-8]
    else:
        raise BaseException("error: private must start with 5 if uncompressed or L/K for compressed")
    
    if VERBOSE: print 'secret_hex_string:\n', secret_hex_string
    secret = int(secret_hex_string, 16)
    
    checksum = Hash(encoded_priv_key_bytes[:-4])[:4].encode('hex')
    if VERBOSE: print 'checksum:\n', checksum
    assert checksum == encoded_priv_key_hex_string[-8:] #make sure private key is valid
    if VERBOSE: print 'secret:\n', secret
    return sign_message_with_secret(secret, message, nounce, compressed)


def sign_and_verify(wifPrivateKey, message, bitcoinaddress, nounce, compressed=True):
    sig = sign_message_with_private_key(wifPrivateKey, message, nounce, compressed)
    assert verify_message(bitcoinaddress, sig, message)
    if VERBOSE: print 'verify_message:', verify_message(bitcoinaddress, sig, message)
    return sig


def test_sign_messages():
    wif1 = '5KMWWy2d3Mjc8LojNoj8Lcz9B1aWu8bRofUgGwQk959Dw5h2iyw'
    compressedPrivKey1 = 'L41XHGJA5QX43QRG3FEwPbqD5BYvy6WxUxqAMM9oQdHJ5FcRHcGk'
    addressUncompressesed1 = '1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD'
    addressCompressesed1 = '14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY'
    msg1 = 'test message'
    print 'sig:\n', sign_and_verify(wif1, msg1, addressUncompressesed1, 1, False) # good
    print 'sig:\n', sign_and_verify(wif1, msg1, 1, addressCompressesed1) # good
    #print 'sig:\n', sign_and_verify(wif1, msg1, addressUncompressesed1) # bad
    #print 'sig:\n', sign_and_verify(wif1, msg1, addressCompressesed1, False) # bad
    
    print 'sig:\n', sign_and_verify(compressedPrivKey1, msg1, addressCompressesed1, 1) # good
    print 'sig:\n', sign_and_verify(compressedPrivKey1, msg1, addressUncompressesed1, 1, False) # good
    #print 'sig:\n', sign_and_verify(compressedPrivKey1, msg1, addressUncompressesed1) # bad
    #print 'sig:\n', sign_and_verify(compressedPrivKey1, msg1, addressCompressesed1, False) # bad


def sign_input_message():
    print 'Sign message\n'
    address = raw_input("Enter address:\n")
    message = raw_input("Enter message:\n")
    base58_priv_key = raw_input("Enter private key:\n")
    nounce = raw_input("Enter nounce:\n")

    """
    address = '14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY'
    message = 'test message'
    base58_priv_key = 'L41XHGJA5QX43QRG3FEwPbqD5BYvy6WxUxqAMM9oQdHJ5FcRHcGk'
    #"""
    
    compressed = True
    if base58_priv_key[0] == 'L' or base58_priv_key[0] == 'K':
        compressed = True
    elif base58_priv_key[0] == '5':
        compressed = False
    else:
        raise BaseException("error: private must start with 5 if uncompressed or L/K for compressed")
    
    print '\n\n\n'
    print address
    print message
    print base58_priv_key
    print 'Signature:\n\n', sign_and_verify(base58_priv_key, message, address, compressed, nounce)


def verify_input_message():
    print 'Verify message\n'
    address = raw_input("Enter address:\n")
    message = raw_input("Enter message:\n")
    signature = raw_input("Enter signature:\n")

    """
    address = '14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY'
    message = 'test message'
    signature = 'IPn9bbEdNUp6+bneZqE2YJbq9Hv5aNILq9E5eZoMSF3/fBX4zjeIN6fpXfGSGPrZyKfHQ/c/kTSP+NIwmyTzMfk='
    #"""
    
    print '\n\n\n'
    print address
    print message
    print signature
    print 'Message verified:', verify_message(address, signature, message)

VERBOSE=True

Kpriv='5JKpPhpoVaibqkFdwWzaPoQaHzNTCRmyjyqEpa67G8msKCiyiuA'
Fromadd='1Ppecdv2jWjZjdSJjnQs5JaGhethCsdTCL'
Toadd='1QFmDXuBr9QY5NoRdbYfZBFFP5cTS9rL4E'
mess='Amount:42 From:1Ppecdv2jWjZjdSJjnQs5JaGhethCsdTCL To:1QFmDXuBr9QY5NoRdbYfZBFFP5cTS9rL4E'
k=1521543600        

sigt1=sign_and_verify(Kpriv, mess, Fromadd, k, False)
print 'Signature Test Alice :\n\n', sigt1
print sigt1 == 'HKaLZ/jSgiehh7cyhP5A7AXfEEwuQudjJiJqQLn2qa6Rc9oH1uZ6LztNIFEnG1Lp4EJnNF/RhXgJcky28lD/j6U='

print '========================='

def rs_from_sig(signature):
    """ See http://www.secg.org/download/aid-780/sec1-v2.pdf for the math """
    from ecdsa import numbertheory, ellipticcurve, util
    curve = curve_secp256k1
    G = generator_secp256k1
    order = G.order()
    # extract r,s from signature
    sig = base64.b64decode(signature)
    if len(sig) != 65: raise BaseException("Wrong encoding")
    r,s = util.sigdecode_string(sig[1:], order)
    return r,s, order

sig1='G8ASwMQNxVKdQpUjwSGFYp+QA+fhUDMqc3fLIArLIG6jckTZab+KCxYt6NzYEStxfCRVh26PEoZ+semt4Kot6j4='
print 'r1,s1: ', rs_from_sig(sig1)
sig2='G8ASwMQNxVKdQpUjwSGFYp+QA+fhUDMqc3fLIArLIG6jE9k34ZhAuDRCzn78Suf5j2uWTDytew3z2iathwdc4Wc='
print 'r2,s2: ', rs_from_sig(sig2)
r1,s1,n = rs_from_sig(sig1)
r2,s2,n = rs_from_sig(sig2)

m1='Amount:701245 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1Apd6spZhPx86oSuKMimv5K6aq69wGxsTY'
m2='Amount:760103 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1BaU9W662GoBCwoPMFC76qgiCqRdW6K9Mu'



hm1=(string_to_number(Hash(m1)) % n)
hm2=(string_to_number(Hash(m2)) % n)
diffs = ecdsa.numbertheory.inverse_mod(s1-s2,n)
k =  diffs*(hm1-hm2) %n

print 'Nounce retrouvee : ', k


invr1=ecdsa.numbertheory.inverse_mod(r1,n)
s=(s1*k - hm1)*invr1 % n


print 'Secret retrouvee : ',s

print 'Signature test 2 :\n'
sigt=sign_message_with_secret(s, m1, k, False)

print sigt
print 'G8ASwMQNxVKdQpUjwSGFYp+QA+fhUDMqc3fLIArLIG6jckTZab+KCxYt6NzYEStxfCRVh26PEoZ+semt4Kot6j4='

print m1
rt,st,nt = rs_from_sig(sigt)
print rt == r1
print st == s1

sigt=sign_message_with_secret(s, m2, k, False)

print sigt
print sig2

print m2
rt,st,nt = rs_from_sig(sigt)
print rt == r2
print st == s2

sec=s

print "=============="

AddFrom='1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA'

lBob=['Amount:547318 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1HeQjRDDGF7iXugWKXBD9xobh6xz1uCsyW',
'HOlJS4z0Kh2TERA6T2X/c5wZkvzKFUzpW2hGJvNxT5zTgrDgMqN323sdF52hDhekc0B7ifddv8bv/3ldMxWD9ko=',
'Amount:655620 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1Bpx4ebEFbsjtWKrDvnKQqjkCz5JdiHVAE',
'HBLa509C4AZAGbMh8mZMfxN2aOtGq90Sw3qqPMVk2CYHt9O3sR+QvX1Nmxfe8gUvpbo9SZHjJTpLqWRf3Cp/L3k=',
'Amount:464938 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:15JYVu3s74vn6kNSFec74sNtzxh27z7Rrd',
'G5ACFn5fh7xax4L1nC8OR/xi+dP8gTl4W545lTZnGerzmTOZR8Zzh+PNdNSL2os42o7xn8VMEpvtKPXfBpZAEcE=',
'Amount:137901 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:16QmcXxMWNcgtXaqpGejdYJKuqU1UX5ZQk',
'HFoB0Sm8sS3u3ibufkSMyTe3kVMNwmYHSANmDtc2aiDM0QTR3jzsBy3bev1TWXjQvsrXIt7X3oRXhLYLACzHRPk=',
'Amount:226797 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:16MDFHiBkT92KrA4sXJAFPnVzPtkTQ46JE',
'G89ZtGgh5FZIqH0EtIqi9zkr9uCFJFz36gx3y0fB36JaoFE0npGRLqUKUjMsfsAum8xbFtOYv634sCfKKTTVpOo=',
'Amount:110745 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:19Qa1y86JxGJmdFzsDGyg4f8CoD1MFGRK6',
'G7ge3vZVYNVPWtn+9teZF3lrfUvO7ZjdOAd0riZxiOsTk0SYXLmLzJwQcrcanL8gKrDm0NsZCXM5TYlDDIjZBTs=',
'Amount:565748 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1NRo6aDhsdA8pZeDzMbYWECgnBwmKcRqZC',
'G8bg7R6FvVUxPaAwH466ouODripBzCqZRSVzPJHKuYPOIexakppLRw87WpEmccqXyYU362i9vTHZjmzdAjM97SU=',
'Amount:629139 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1AKXqZWWxhmaFfBYH7PQgvG8rghD5nYjHj',
'G1z4NxgqluNv3vdGCQKeKpJtAsHLIhOX1Tu/W657UTsX8Y2nwP7iJt/VWiaIHZYiz/QGi7rqxCtJ8qewkgnIEtA=',
'Amount:335543 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1776ZZa4Dg8xtPxxAfQkzEwpu6JmcmroRj',
'G1Mv7LRqNZzfoLZTlvSGmAvmb9FihqSfuE9E+QADrnL6uZWu9NMkPqUGp17uawz3Gy+6xkSbEO+Bl8E5jaLC0Vo=',
'Amount:772098 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1AjmmHvRZK929pg7nmtgSevVZCPHnwt2jb',
'HG7PYH2Xx/Vwp6Pj67ED9YDZOflWVnwR3wQFEdScS6f1bm+AE5GtqjgBY9sqzkr1r5jW870zFPK1OpEi5dCKJQg=',
'Amount:923483 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1BoYTKoAgchCYzDQvpUewZjMwzPq78ZgkE',
'HMHkvLVClnAPjtAeqHlE4NEoBKQr36K8mGY674F0BgA9PI7+G5fYnF8eXl01nKxGhARYbW8Ey/Xn9IgEfy9whf4=',
'Amount:394766 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1NFeeMj94nxsx8CvvcXswj6gwqtM521zdn',
'G24vOwURaaHyPV3RvC+mNWdF7Z6OROI4WjMQCF1SqCz8aqeRrcvOj+VqwovvnFkyCJyO6+Uh3whulPxitfjFGZ4=',
'Amount:698452 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1BULimwDd5DGJV9xo14EJjZpMe2rpEe7X2',
'GyJyfBgOXsrUee1LNxpN/azru+f84kQKO55Wi7ppjyOlS2Jq3P801Za4WTTvYIXOZvY2pLysEtPh8WdxcP4Uivo=',
'Amount:95725 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1DSKQq3iYb6fHwrGrp7H8GmpXXKe89S5Ab',
'HE4agu7KOWjcpchh7uaBeFgiQiz//nxTEdtNJ1qJDtTswmcXjH1sPYEtaDXDR4fR90JYHjtUGVX+zIkTXtTYJVI=',
'Amount:560932 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1HQwj5fK8fNtY3VrLyGupJF5rsnjosFknG',
'GyeYdMCZPfJdnRg66pOqRPb2imJdE2yUVAXey6mxoo4Si4rkOp1fEAL1u2OQvz2D6XlUdfB6gy/Ge50yTr48JVo=',
'Amount:26703 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1AUihPAWBxn2qSwq9qFDJjEsCoMgYTfMTA',
'HMYCg2q4FmnKWmD6+Gfvub9sLvKwJY5ceEGBoAOb+CIF5QGG5404yg9gv7JQrcGnwiUpJcaRygNkJRv/MxCJ3CI=',
'Amount:544707 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:17JafNaYXsvqVkUXWKJ55KQKDy2DdeZPqN',
'HDiDdF6Yx7txuNEX247azzOtFvC7juYC/JLqsGjk0o9IVvzctir8r+lQLJneyw7lasHy953Pi1R1TI3K2b0EwKY=',
'Amount:687328 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1PkG7j9KrKwZMqJbzsEEQTY2rGwmTHazpz',
'HMStLjxJT6cD7LuMGUb1eElJF4KEUjWnzBncGpsdkJ6JzWXhyuwRRPtTMmIJb7YP87xihvcC7421vXm40PVZPxA=',
'Amount:183764 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1GuakGFKie2sWMXE2CqnukW9uSF26swwBy',
'HDM5RANNZXJMO2xr8qNPMo/2MXVyiXG/yNezpyMmsnaD11KSaKFnBsWc4jsCiNmOTuHBFn2oGj7MpDiHto3HtOQ=',
'Amount:264512 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1QAit2arC1bNwRqMBgXtVEVELh2djCEUwa',
'G8YY96BHkoRrPlGJOo45pfHJpcdoOTmOcChTkHVdFlwTIV+o4vme00+Gbul8Rogt0KfmJW22AMTnOY+BHxZ62hs=',
'Amount:8232 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1DApETbRYuqdShVvHijxS6CQ2cGc49mu8F',
'HE9GjWP5JLxrIRwDLPrgPJySVWM7EnT1fsUKH2Zqle1e5ffVv/7ONXI/6wLdA2nVKbLAfFivI1A7P/CMPnqwZfw=',
'Amount:961023 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1CmLukDAA4z19pe3x6XobJYeQjoDdysBgm',
'G0YlShoAhRxbAI4aVH7gN23adRVgFzslXWzvoDdjELJOSgljlbulXl47HPqUDe598/ZIo3VVELXkO0UQu6+LbT8=',
'Amount:907119 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:16ZdL4A5DpPsCkRGp3a9AoDGStANh6NAZ5',
'Gxt8XccwOI2NmgEYKPz0elDa+9s4Pi108tGZXQgsC8nCLB7j/+JQYYYFVdZUgbxPQlFZtU+qDMqw2H27vZzY0RQ=',
'Amount:55898 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1DKUP8DjuhsDNJe9STaqZ3NkcCCA13USvP',
'HIYemoat+bp1xbOjLmbF52X7DmyNKOX6W+TD6NEIOjUzlyhJ9STOFZ1H0Po42wpQ9GBtMxuYS7Pu8EWdp3BPYhk=',
'Amount:950065 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1CKgegpet5LqmfZTAqKPFvCHqYVirS3xGV',
'G/X4wGI4nCirTk7tCaPAbYFMPbeFHVoJJc1G3Mkpc50te7SjONZSKVPnZpjj8jSNIluhavZXaC2+FIFWvn17C2Q=',
'Amount:799476 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1FMj9vcKauv3qV9Wn6XUdFSNn7UftfLXD',
'G042IOmMZFUAde9RFfbKKZd+JpBZVdYwjfg0eDI01HgZejrFqIa/Y+9Kzyfj+A5vnK+UX2Ogi96QSArJYMWt4OM=',
'Amount:615631 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:13NoGzXYA2DHLLRkMhg9HmJMQy2HfPZkUN',
'HGXXQMW1FF+Cbt3iTP0e9dpnXRna+Qw4wa0ybGbYMlJQuRCAZsFU26KbJtrQbtMV3RjjMlj15c/WaC3pUBXlcxE=',
'Amount:396995 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1NXXr2Sj7rW1zvxXQVxGzPUo2dQfg5Z8Zu',
'G/+jIgYAMy+uCphIz0o8g8P86AWSlUuRSLmVK15cwsaqg2QNSq7qarHtVGjpmrY8VSL4sNDGpgh7DGN+tXdg9/I=',
'Amount:838687 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1DxaH6J3A7A8nabzT7woNdZnUn52pLM2iV',
'GxKJTgI/3+u66nNe3q3eAZTnjIz5zpfXS9zCyEimQuDypzSCR8hFLnfZfMNNjPrNPp+9o/22aXdvRrPXgACAXyo=',
'Amount:493120 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1DUnA2z89hL4sVScHifpvm7jZaEE2eep2m',
'HGGrFt9xzjDa4ursUVxqLEXMHVTm9W3U+9l62FHI3lss/SKwHpL5GYwYWwNqdCdNHiQM/CQ8TqmZjyEGdzVV2Wc=',
'Amount:900080 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:18WmX2xX43mUjaWYmeyQMCS64wJPD4AXZj',
'G1mYDLvSY2c2czsqcxmygSBxExlmhrvZYdVIYaAwPr3ThQ9ggOOvZR6REMXg10SEwQPpKgTbkyQiJkJwYbZj3r0=',
'Amount:891695 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1EYi2rdDYgdNaJMUQu7TDuMJUJA52JwiZV',
'G08Q7Yew61dPChLRpXElbKlHZCYmBuMjMBzOKoimPelY0772F3fUwDce/+Xp3siGbV31jGoAcCMiI6T8cF5PqEo=',
'Amount:75194 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1Jii4Hf5khjPZGjacxvc9mdg7JksED63ba',
'HNNz+S2HXv5i9ITk9XoWllU+X7FUgGUboxsDVUi1V7xsPgQj2SfkNf3gaRPcC5v/0EDaY1fU9L3l4kcNdtJZtZo=',
'Amount:539698 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:13ZyupPe6R5DKfjk2oArTUK8GNtBoLJ66s',
'HN4S/iA1TFX44NtbWLdoQVG2wy6+KWuUwxJSCDAWLNRCvv0va5sdrvUAhn0MsbS5CX3k1oT2uGg5rc7VcUO9ri4=',
'Amount:41824 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:16kNX6H8UbTSjWrP6n4T7Zx2zoJv74XdZP',
'HJ1uyCV7UONbUq81pAcWklMP0OwIQsYVBNHhEjYl0m6cgoXO1x7jCmI2ahMRK/4RoTWq8wyrQk3R+dfK81bbZ90=',
'Amount:993877 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1PdwrPKHEGGjgY5cziApvyhXPhc77n3DmN',
'HKfAVRfYXfgGY+cvWJiQSXRXpIYNoUmBHkvLUEBxFK5BVRa5sPtcLOOIBdlSsmMiczkp7XTk2QzPdxSJyM3p9OM=',
'Amount:590161 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1LcLMMeg6QYBvkKpLvQpoFHXG5DX3LuR2J',
'G/2jJixMc6QMB0xIc/Se20KFQYB8s8GlB58GM6LeRTEnte4719C311k1GuHyZKx1fZSXZl+BgOa4nIQ8G7KuRH4=',
'Amount:468431 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:19vfdv7KUyNmsPH7V6fZHX3CEcspdN23iF',
'G7e8eav6+VJ1kabtQVOPQT6VyOOx5onzyp0CiLwexrUpuq69FhbaoJtnb0IxwaTMedzJ5wwzK/QyxPnEiDFYfRA=',
'Amount:829873 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1K4nyjF7Cs8PrXntsymp2iiSqPoPCjAHpg',
'HLPV4O9c8IEiQ2SsDZ6p1oMwruASN+USLdRa5/w17NOSMjiWB7L1NwA2OGRB5WVwR70qj/KJUBgOhLH1xr6FeZQ=',
'Amount:267427 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1ESANwNswe9ahe6ndkY6VfTADV2RLBZBP1',
'GwN59m8hux/y6QTLRVj67GJPqyLNp3k0i+KWCo7SXLa3Gqs0mJfKIhq2y/KZ9j3imZzIlHz6oMW1rKY3kucPDD4=',
'Amount:587853 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1Fp5DhM4EkszJAMfQvJbH9ZDqygzPmS54S',
'HLUSuLZN1x7sexCDBcoZQM5mrgJFnwwnjdPi133yrlsLYp9H5Bu3Nqk5ghOmVmKyEeDJdRvDmf5AtnB1zT4KUdI=',
'Amount:367518 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:14ZR8BF2mZK2J194Am8Z4PVFjJg2s3mLbQ',
'G56e1r5FqxGOLeevpyGVkJ/Zmiofox5T7T5Ercm2Go3d8/mVvOilc3+ADXZXLRMdtDj+FSMeE6okkY/fXBUAs8U=',
'Amount:449351 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1FtsYBuWECRGQ83b7sHd1vKULzwpmD4pwg',
'G2Z0xMesOdWjnj8MfchCVeDRO8Io68MHMgDM0dSuD3VkEXqSz5iLEI6cRfdJZSr7cyRwCVjZ/XOI9++TMKw4J5c=',
'Amount:145805 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:17AwbBrCbPK25GeC7vubPiCQKaVd7YYEoJ',
'HKRG7OCOYSzVcdAmY8NS2IMsHyFlixCLlDPbBWTH1afaAl61VMxCvTG+5WHJv+UWRB5iqNSSErr3dE3toeMc8m0=',
'Amount:319025 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1MQMT2VSbWE8jYCENPvybURotExAc1SUxz',
'HFP/piOBFNIl/c8KffIJqXzThyE38+/5GIprxlVYdbxy71RPn9/mcP/BNJLVmHPER4KWQ36MppVKNBexBX8FQqk=',
'Amount:501220 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:18HYJzWYNFnkok8zPFqRFYPvKnZLDB7ay2',
'G1nQW9xRP0n9p6dcExrJ8jZ5/IQDHg1FkmUC+IMmYYSNinZdsmGWtpZmYgLuNMAZyp0I1Qc1H4DuzzQMjtY7kzw=',
'Amount:333059 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1KfMk9hp97ivDBwdrjSE8Yqimm1xmnD4E5',
'HN5B94myZ8uYqsXN1E7ggJMy8Dsz4EUUEBo34GOV1rO57Z0EAlXDgKdt2GdYKTd3NrG804DqffXGJ7tqn979YRo=',
'Amount:963692 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1JWHP3GhKjbhpCjSdwyDENNB9hS6kYGNAv',
'HAI8/CqOZzDxdPlP3ROdzUzPTPbz1Aw2oCVP6M1an779dDPNG7GzbjvCBIoPnKeH1sqm1RsYMt4Wh0M/ZIkoKI4=',
'Amount:378909 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1KmzfVjvGe136oggj5J9bTw3jVyfZXmJDE',
'HFWyjCC1CldokVS4sdTLeRFwgyYFPrMU1MgFKhg+qbpLfqANpSixUiRe1hEIUr5JECUSCuPyuIl6Zc941noHOLQ=',
'Amount:788861 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1BpB9T2D6YG2XMik2QixALrNMwqeVkjuEY',
'G5DU0F6Wf7TmTWMaLDyblzypTcy8hmunTJ6MNkcvBKXR3dvl6DugC6AKL0q59NbeZwOId13J4YLpQ0CqblpBx90=',
'Amount:317442 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:174cFpXoCCVqJzy86Lz5hRjaQYykXZ8aPb',
'HC4TzQ4j5Y5O1rkeypswtwdeYMnF/LNRm89b4S8/rpBgCSrJvFuOqB5WFZdktSHz133hmjPoL8d2j/BXT4B8QKI=',
'Amount:458700 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1FkK4RbMcSmWRoFBKAQ4pSW1mdaWmxWqA5',
'HF3d2KhT727IbiAwYw9rSgWnJNZC+KeaHoNzbOEgr4dmVepVGKzjIIge8wYb/Lv6e5m3ewEBvOdGsNDiVAA+lpE=',
'Amount:878459 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:16jRNNfmhbzMMumZYVuBDJgwGoJo7tbeSb',
'HFHwCBAoWR+mxs7flIybczl3Pzx1dPC/KjyvHmPsKSFFVu4eKnfuC3wGo7vQS1XTjA+ovKNGiQ+fBG2EZBbMYMo=',
'Amount:21329 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:17u1h5Fg1MX5BiBqw65Qa2PX2fhxyETYbL',
'G5QdSFjTFsPHnOTJ1j23a/bY8QpRJ5XjWDhts1DeZN0jark9i8NfzoxbLq/+b5uXdkAQ2SEVwgXMOL5Ip0/39vA=',
'Amount:138372 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:15z6nbKoG3JFZjeHPdmSqdXbHGi1GHYFSr',
'G9Dbo5Xpopz3Eg3O2XmcwZ5ktuItf/ez9d2uKx8YYAU02eKszbMlYMs3xU7ruxejJgSh6weHI781bSaUUk9YL2Q=',
'Amount:538058 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1BJRii6FRb7k7hVzVPuBbehiBxUVmtPqJ3',
'G/NN+da72nQO78puzYEhRao1uQ/Svx9SYa+67+SaGKAzD0xoFjInJUnN1P+iVEWhWH14t1erCIyKqPobt8s2fJ4=',
'Amount:159764 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1Nht6rVZ8ZomxW56MJCyGWRY4YiXjeYnmf',
'G7A3ybSrjOFvXQ7tW7sH3zIPpptoUAL7oXjtEpe0Ghte21YILg3TNdudXnzUbL02atIbQmvxwXfYEk63eEfy8Yo=',
'Amount:663310 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1MD5WRnD4DMFwmaXgBmFdPH2aEkPAdbbkL',
'GzEviI+4RHInKYnbnbRw1DF9szOAoPmBrTXbrOEeiXLS19IRAxh5bx5dDzfonZEd1kSZKJgO9SWeLVLsPKNevkU=',
'Amount:281711 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:165FxCQ4BqwZDpKTQjTrHjxJpYUcphfaM4',
'HNV3MUOcxICWfbY/lNKD2eXXuDVdww+6yuK++KCmYDhCGfYPjYM9C2jwR7xvPEEZFp2X1Wr7CmUkOYNwiw/FlfU=',
'Amount:865755 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:18dYf6CM5a4tgus2y2Gkz9H9N6uKpue2dw',
'G40DF0EPj+x8dOkdTMOhy51NxpFZQTuuWUZ6cUNTCgGiFCTN7Qcc6QTBxIyJwXdpZjMTk5xM+pqAjlfwdn4CTQM=',
'Amount:683942 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1GgKhb8NkKnPnCb1NHZcK17EwGVJ82dBbB',
'HGTMY5Ma2BYesoCFjBRjT7sbPV6eq9Uw2oHoRRiUDNXIgfd33VM7Ad0ATEMnV7cSh09WKFUMrtdj55NhVhawC4g=',
'Amount:785445 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1NfHJ6Y7e6JThVUxhgczUrXFmPnxqZyCjX',
'G20TrR0GAjT2/hTWvhrSsBTx4VOhJ4ZdtnxHbYBsy+vYrZHe0cqodNwHedOYqTZi79V3jNwRiELxGo1HoIZES0I=',
'Amount:844088 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1B2XPxMTPsjj7b21ZukXCe3n1JgwrZByqJ',
'G2SXYpCvEd5T6ElnVG05emkiNRGMhVzoj51CFh8pT/0315voECa1zwHW1KN46eXUTGnGNtxzHKnIJyF47BX+ftE=',
'Amount:851928 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1JAA68sgjo4ip7ieTz75qAp2evM9jdczdk',
'GzQbnRNGChxintUE7IXOi5xtvMNjiDqcVX687oK1iI6rBHiZ0SO93y9UlpumDfoPSR9DumJExTHwoMuvkQb4/s8=',
'Amount:701245 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1Apd6spZhPx86oSuKMimv5K6aq69wGxsTY',
'G8ASwMQNxVKdQpUjwSGFYp+QA+fhUDMqc3fLIArLIG6jckTZab+KCxYt6NzYEStxfCRVh26PEoZ+semt4Kot6j4=',
'Amount:893506 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1Lh6YquRVKmKLw8vUSqCwgDWuFNXj3Zb9y',
'G/lPHUxYOtDQf0JlSgC9TbCDpstjSNYssli1pU2wt5ISYtUO6KM4oZFYSN9pF5K25ibuGXdFFmn+uY9GtU/yvLs=',
'Amount:761463 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1PSSH2PYNYX3oMzmmdnGrYDwRUD2M13CRu',
'HKNI+oHPdOO77XmCNvuCBLY6U7aT8G1RdM7eg07RvVugegPVouYDOTpTfHpDFLMH9O33GruAYC/mE0m9ommxhyw=',
'Amount:928195 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1MRkg5vRj4sLShmPs8pyrAJCivu1qgsGoF',
'HGdmTSKWbtyJU/ne7CPx34euxASP85+6ZTVavE470ehNvLQZUjAnKMne3FiECS7u4eioKHHBCltG91IoJJTvlFk=',
'Amount:527625 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1EoJMiVrQf13u4P8hnYN8uePQkHz57Rp1E',
'HEXI40/NOj3SMfXF+szhnIFq5xOnHaTFSjLEmlfuxCVgpjLz+R9VJlgB638H1ZO07KSuBsM9lmc9ku2yNhB/yr0=',
'Amount:14388 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1Mqh9ciS6JQhsjf11oVYqtyaxBw4rKH6ts',
'HJLftovn+yKVgUW9iBhoHSRo9pXnN6+W+aWDjxcWq/gj0dQI4gknHiKcn22fUTJzt3BCqr3KoL8VKTgGTPsrN1s=',
'Amount:772072 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1J9bNGdj1RtT2f9rcVXzVxGmC9NdqVjXaQ',
'HCrIRTmYkdHOSpUWybOCCqIAw3SgWPEItLkUR9bGW6qTh89LUrkitm0JIj7T+D9Bcq3ntTbSB/Ynh+0v/J92m1A=',
'Amount:109211 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1EaYJdWpnGP9pGf5qQZCu1sFC27pvfuWtQ',
'G2Urxu40AqXUMaEM+ZTAlW7VxWIsq1JHt337RjHyO0niT5BOO6av4s19MDKm/7CXrNBPx6e+KvKSO1aJ4QXYP6M=',
'Amount:784602 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1J3ZrJeAmVDCf6RLNg8ADbjc896SUbi9uh',
'HLu3+ysmTd3nyUvgVQBIKRgzOGiXeAQG0fB6TU2Heix5e00VO/eD7H0BnZwn5/b2A9iE3GRTf5DHa8OapbaxkRA=',
'Amount:795138 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1JCR9NX3qa9DUfoTtkQznhsms96Z2cajqC',
'HO9W5C2/L/SOZM4Gw8qrXF0m7ap8qVpRl675JPFqYXiWJf0+Fr0NyAmf5RPcirbu1d5/h5UsbBnD51dc4S89UGA=',
'Amount:964851 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:15vx99iehQoTwooMipvqxsTfErWvs81U8E',
'G5mdWwGvsUJvMTuXaahVBMP4XIkbwLU5AmLi72AKk7U/q6IYXQw4EOyDd7IC2+THr/3na8RDrIlTYzWtxl1MCns=',
'Amount:736532 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1JUAFmNCQfTNNP5MmyxuaRTyAmUUn25Epy',
'G26O3nV/7fe+xF6xyQkNE3Iw5L/B/GzDW/rt1IQHMpyq+/oHwUoG/CU/VLjFO4JXGNdCgJwEudSgweksHHiNTJc=',
'Amount:777907 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:12aHxGJ33eBreLEU2kxqohhvXrsPZXJfNc',
'HKWqPfpqscFhUVEJrVG4g9BJwG1dVMN58pSp9ZNkbCeOXRLW7Je3wZ77BpwJa6J+uqg+J4vJPugqBQEoOP5lsgA=',
'Amount:460012 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1ArX5F5gr5mXSYNzMsepYRquHaeJ66gqW6',
'HFWkHfEABYrYYqincApO2VAvCsGIMwYFTA7KkRoAiXgaxS1jUOGZAuYBxRaUBHF/itoe2n1S7Prgy5Lo15vvS5Q=',
'Amount:488483 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1BseRgoPJ1iqohnniYhxRGWByMVHGcUstv',
'G1fQOmCTsthCyE2FZROCq9avvbbDADaZsAWxiMReP0a8okhfddXKMj2muGXUE6kzSp/NZc9CIZkXc0zDns41v7w=',
'Amount:339204 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:19w666i5euvPXy9LUNM3k1C5u7cQgCt1Q6',
'HA1fA28ILuwZWzvDBCpHfIipTw+5Ebkh7aSSaabnCmnUgdxy41HISlK/NXoMo0ndEGGhshj+MQJxDsedr/5j4H8=',
'Amount:591748 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1A587b7bUVY1jn7RQRFwWQbBzUVLsdGso8',
'G1ougXmANgPXYP6Ps/0UhSz5s7OhOY8AwzqpJWEP1EweKKccxDSfSoogHNIMCa42Hohsu9n6qfPk+6yytW1L/iY=',
'Amount:806022 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1CsxffzUMxLoFvV32EE3j76yQ5qoGsF3oC',
'HII1Ap536H6HLNYaoYiiUAzgNcKYtE4so7euMtmbXmm/Ri9/N95cQm/MAJQJDeCQir/T1wnMywtwiMVIC4w9B1A=',
'Amount:966582 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1LEfuqrffE4ruiz7QNdTbvtvQDTDo15Epu',
'G9DQuKAVL5s8k6uUO9mBd6xyOq2OqFIlYcwWQnPrwyAm2ThMhRrQZPZyH74h055SCu9HyxBnkWA6UCl2tDdbY6U=',
'Amount:767889 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1Lb25LU6SDi5CaQq5jFAJb8SbmJY4FL215',
'G7cZhegecJs5MXfIHASvqUeSOMiwiTzEJmYpzsr+sERoC1CzU78ChcHYuudGOcYdb+cM387vXSIKqH53obl1nqY=',
'Amount:760103 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1BaU9W662GoBCwoPMFC76qgiCqRdW6K9Mu',
'G8ASwMQNxVKdQpUjwSGFYp+QA+fhUDMqc3fLIArLIG6jE9k34ZhAuDRCzn78Suf5j2uWTDytew3z2iathwdc4Wc=',
'Amount:47681 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1GY68fS6PsP8Mvhpbva5UQQubJ9QgRATr4',
'HPOSIv2nFo9GhwHKYSofIfcby/KmB3GbAVaJZCMtMtJ7Tr+gI6BdIN0u6oNUeT8ugti4tU+sD52d7BIlXh4cmQQ=',
'Amount:456675 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:19pSJqqwnKRy8SB4Z5kjcrrspgGpTgMj1M',
'HJH89Kt6DRZ1aXN9j4p9b4Oux2YqiX56A9DXtYNCNeQqcqkoUnPhzuuQ71nwR/Mk0J+pMbs7KT4XufIGA+fWmjw=',
'Amount:301107 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1KhVCDyfHgpJkcAxdN8S58BoRu8g5hFnvQ',
'G6rnWaCfkcInToOqaFnOuRb+wlcT9DOxs90Du9vh9du2v+S01r/L/yGVUqo/tfdUjtv5P0teU+RekoK1fwaVlsw=',
'Amount:795660 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1FNL5phmaFG2mgej6Xg1XYQgxF18L2LLj1',
'HPgy/G/VuvFvyNrhFCLSb1MaQVi4K8rnGREAO4keZnmed7j4f3S5OC/G7txPCEb0pmJhuBPj/Jo0dPqerKbweYs=',
'Amount:114646 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1Kbc8VVTStQP6z3f6qFK8HwtWMwkzhWwU4',
'G9q62B3d5FgF2p56JO8hKB+URU2ejrXuoUtSrRSaZkakHkRx+cciJuy4tY1HK2TgdcEZVntSArz/i9rox8xlJTY=',
'Amount:819996 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1HQq75qrByRmFTRSM9LckYStbVy9e93AWr',
'G12JHg2ajvNdIh0qX9mLq5kGmz9YcW3pLdNQtZ9T4rHcnqOq3SqweFCd/oNZJhnxlTjrvSjtnGtQIS3EupETA/4=',
'Amount:726400 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1PBPJKRSTaqWgALpfow78APkiNf7oVYuMY',
'G3jwg2g/J3EMMfpsFxrkJrkA4tt1hWD41jyFdF+8bypMi39W6PKKIyg1tmXJKPRIf/Oo2o+ccvJ+7iv6rBtsc/c=',
'Amount:609569 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:18auUeXu2UgxbjszUVaKT6FAaDNBTDjupk',
'Gz6My+9f8tAN6ZHFIvEzxt3rJ1VtVb3HMEwh//A85GCL/ed+8SFMQbGP8If/jccpsQPgtiwfspmy58BPi7ABT8s=',
'Amount:936633 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:17Ypa1dL1SY1kKv482GFrJvxVz5h7hrfoa',
'G3yA//5uqLlHnkistpKINlzwXpqfe0J7IDpWhUEIeq3Nu2mRp1eqXEInQA2oS4KXGoBfSru+b0NjN7Y90SdmN6Y=',
'Amount:374790 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1BqEB7zbainpARLG7xuMFfYR7J1RrnaZoX',
'HNwAWIRym9absBjFfJrDvpvzrEglAa6y4loW8HrKs9m0ovvmKCYZjUDXbJtZSeYkP9FoHVm9gv9UbXsNbABcawQ=',
'Amount:521332 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1ATFVvfMVwn2P16S23byPxqwmPHvqs4x8o',
'G2rmkiKS1SNliKtnYEerkbz9Va08y2twx1Z3dRLWKvd11Jia4+b0j92MvVyYTDU8HFobAu6GIBj9OFdvznFeXtE=',
'Amount:296290 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1CxowEQQXkDjjk1KKAPkh95TzoXZEmCDZT',
'Gwjz87mIvmBsKIEJvUZxTL6aPZdUjW7ZyFAMPeXPNpdyzf2NRXbrdH8IhYayYCN3mCS4AfMzY1H3wTFiDU9bEV0=',
'Amount:856437 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1KRPdZrJYyA1Cgu1skzAopj7pXiteRJkiL',
'HNSkBLo0zaoU2sKGuDCgpruRNYfs6IcMEkobyHd+a/ggddXa9IHyMiorPs3D5TO6PRPf4RTZz0JtsH6GAxZakFY=',
'Amount:589534 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:17MQ14aCkYWSY1G3tvRonBq4wLbr7HtSgx',
'HEralrCNXqxMgt+fpGw1gKQM1aw8HX/wFxA0FqzEIjMETlqa8KNx8Bwzwm4Po5ESBT7OL/YkeKv5Hr5n63zM4x4='
]

lnounces=[]
for i in range(len(lBob)/2):
    mess=lBob[2*i]
    sig=lBob[2*i+1]
    r,s,nt = rs_from_sig(sig)
    assert nt == n
    hm=(string_to_number(Hash(mess)) % n)
    invgp=ecdsa.numbertheory.inverse_mod(hm+sec*r,n)
    invk=s*invgp
    kt=ecdsa.numbertheory.inverse_mod(invk,n)
    lnounces=lnounces+[kt]
    print "Pour le couple ", i," la nounce est ", kt
    sigt = sign_message_with_secret(sec, mess, kt, False)
    assert sigt == sig
    print 'Message verified:', verify_message(AddFrom, sigt, mess)
    print "=============="

print "Les collisions:"

fb=len(lnounces)
i=0
while i < fb:
    j=i+1
    while j < fb:
        if lnounces[i] == lnounces[j]:
            print i,j
        j=j+1
    i=i+1
    
    
print "*********************************"

mess='Amount:1000000 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:14pHuKrkRhLKsW6zxHKQ64DFGyKQffj7GW'

k=1521543600

print mess
sigsol = sign_message_with_secret(sec, mess, k, False)
print 'Signature Solution :\n', sigsol

print 'Message verified:', verify_message(AddFrom, sigsol, mess)

print "*********************************"
