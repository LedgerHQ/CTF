#! /usr/bin/env python
# coding=utf8

# ECDSA BTC of CTF3
# Copyright (C) 2018  Antoine FERRON

# Some portions based on :
# "python-ecdsa" Copyright (C) 2010 Brian Warner (MIT Licence)
# "Simple Python elliptic curves and ECDSA" Copyright (C) 2005 Peter Pearson (public domain)
# "Electrum" Copyright (C) 2011 thomasv@gitorious (GPL)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>


# Signature is done with a random k
# from os.urandom

import os
from B58 import *
import binascii
import base64
import struct
import hmac
from ECDSA_256k1 import *
import cPickle as pickle

def load_gtable(filename):
	with open(filename, 'rb') as input:
		 global gtable
		 gtable = pickle.load(input)

def mulG(real):
	if real == 0: return INFINITY
	assert real > 0
	br=[]
	dw=16
	while real > 0 :
		dm = real%dw
		real = real - dm
		br.append( dm-1 )
		real = real>>4
	while len(br)<64: br.append(-1)
	kg=INFINITY
	for n in range(64):
		if br[n]>=0:
			precomp=gtable[n][br[n]]
			kg=kg+precomp
	return kg

def dsha256(message):
	hash1=hashlib.sha256(message).digest()
	return hashlib.sha256(hash1).hexdigest()
	

class Signature( object ):
  def __init__( self, pby, r, s ):
	self.r = r
	self.s = s
	self.pby = pby

  def encode(self):
	sigr = binascii.unhexlify(("%064x" % self.r).encode())
	sigs = binascii.unhexlify(("%064x" % self.s).encode())
	return sigr+sigs

class Public_key( object ):
  def __init__( self, generator, point ):
	self.generator = generator
	self.point = point
	n = generator.order()
	if not n:
	  raise RuntimeError, "Generator point must have order."
	if not n * point == INFINITY:
	  raise RuntimeError, "Generator point order is bad."
	if point.x() < 0 or n <= point.x() or point.y() < 0 or n <= point.y():
	  raise RuntimeError, "Generator point has x or y out of range."

  def verifies( self, hashe, signature ):
	if self.point == INFINITY: return False
	G = self.generator
	n = G.order()
	if not curve_256.contains_point(self.point.x(),self.point.y()): return False
	r = signature.r
	s = signature.s
	if r < 1 or r > n-1: return False
	if s < 1 or s > n-1: return False
	c = inverse_mod( s, n )
	u1 = ( hashe * c ) % n
	u2 = ( r * c ) % n
	xy =  self.point.dual_mult( u1, u2) # u1 * G + u2 * self.point
	v = xy.x() % n
	return v == r

class Private_key( object ):
  def __init__( self, secret_multiplier ):
	#self.public_key = public_key
	self.secret_multiplier = secret_multiplier

  def der( self ):
	hex_der_key = '06052b8104000a30740201010420' + \
				  '%064x' % self.secret_multiplier + \
				  'a00706052b8104000aa14403420004' + \
				  '%064x' % self.public_key.point.x() + \
				  '%064x' % self.public_key.point.y()
	return hex_der_key.decode('hex')

  def sign( self, hash, k ):
	G = generator_256 #self.public_key.generator
	n = G.order()
	p1 = mulG(k)
	r = p1.x()
	if r == 0: raise RuntimeError, "amazingly unlucky random number r"
	s = ( inverse_mod( k, n ) * ( hash + ( self.secret_multiplier * r ) % n ) ) % n
	if s == 0: raise RuntimeError, "amazingly unlucky random number s"
	if s > (n>>1): #Canonical Signature enforced (lower S)
		s = n - s
		pby = (p1.y()+1)&1
	else:
		pby = (p1.y())&1
	return Signature( pby, r, s )

def randoml(pointgen):
  cand = 0
  while cand<1 or cand>=pointgen.order():
	cand=int(os.urandom(32).encode('hex'), 16)
  return cand

def gen_det_k(msg_hash,priv):
	v = '\x01' * 32
	k = '\x00' * 32
	msghash = ''
	for x in xrange(0,64,2):
		msghash =  msghash + struct.pack('B',int(msg_hash[x:x+2],16))
	private = 1
	priv    = binascii.unhexlify(("%064x" % private ).encode())
	k = hmac.new(k, v+'\x00'+priv+msghash, hashlib.sha256).digest()
	v = hmac.new(k, v                    , hashlib.sha256).digest()
	k = hmac.new(k, v+'\x01'+priv+msghash, hashlib.sha256).digest()
	v = hmac.new(k, v                    , hashlib.sha256).digest()
	while True:
		v = hmac.new(k, v, hashlib.sha256).hexdigest()
		ksec = int(v,16)
		if ksec >= 1 and ksec<0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L:
			break
		k = hmac.new(k, v+'\x00'+priv+msghash, hashlib.sha256).digest()
		v = hmac.new(k, v                    , hashlib.sha256).digest()
	return ksec

def hash_msg(message):
	message=message.replace("\r\n","\n")
	lenmsg=len(message)
	if lenmsg<253: lm = bytearray(struct.pack('B',lenmsg))
	else: lm = bytearray(struct.pack('B',253)+struct.pack('<H',lenmsg)) # up to 65k
	#full_msg = bytearray("\x18Bitcoin Signed Message:\n")+ lm + bytearray(message,'utf8')
	full_msg = bytearray(message,'utf8')
	return dsha256(full_msg)

def bitcoin_sign_message(privkey, hsmessage, k):
	msg_hash = int(hsmessage,16)
	return privkey.sign( msg_hash , k )

def bitcoin_encode_sig(signature):
  return chr( 27 + signature.pby ) + signature.encode()

def pvtoadr(pv, compr):
	pubkey = Public_key( generator_256, pv*generator_256 )
	#privkey = Private_key( pubkey, pv )
	return pub_hex_base58( pubkey.point.x(), pubkey.point.y(), compr )

def recoverk(m1, sigi1, m2, sigi2):
	G = generator_256
	order = G.order()
	sig1 = base64.b64decode(sigi1)
	if len(sig1) != 65: raise Exception("Wrong encoding")
	r = int(binascii.hexlify(sig1[ 1:33]),16)
	s1 = int(binascii.hexlify(sig1[33: ]),16)
	sig2 = base64.b64decode(sigi2)
	if len(sig2) != 65: raise Exception("Wrong encoding")
	assert r == int(binascii.hexlify(sig2[ 1:33]),16)
	s2 = int(binascii.hexlify(sig2[33: ]),16)
	assert r > 0 and r <= order-1
	assert s1 > 0 and s1 <= order-1
	assert s2 > 0 and s1 <= order-1
	nV = ord(sig1[0])
	assert nV == ord(sig1[0])
	if nV < 27 or nV >= 35:
		raise Exception("Bad encoding")
	if nV >= 31:
		compressed = True
		nV -= 4
	else:
		compressed = False
	be1 = bytearray(m1,'utf8')
	be2 = bytearray(m2,'utf8')
	z1 = int(dsha256( be1 ),16)
	z2 = int(dsha256( be2 ),16)
	# k = Dz / Ds
	inv_s = inverse_mod((s1-s2),order)
	k = ((z1-z2)*inv_s)%order
	print "k used = ",k
	# d = (s.k-z)/r
	inv_r = inverse_mod(r,order)
	d = (inv_r * ( (s1*k) - z1) ) % order
	return d

def bitcoin_verify_message(address, signature, message):
	G = generator_256
	order = G.order()
	# extract r,s from signature
	sig = base64.b64decode(signature)
	if len(sig) != 65: raise Exception("Wrong encoding")
	r = int(binascii.hexlify(sig[ 1:33]),16)
	s = int(binascii.hexlify(sig[33:  ]),16)
	assert r > 0 and r <= order-1
	assert s > 0 and s <= order-1
	nV = ord(sig[0])
	if nV < 27 or nV >= 35:
		raise Exception("Bad encoding")
	if nV >= 31:
		compressed = True
		nV -= 4
	else:
		compressed = False
	recid = nV - 27
	p=curve_256.p()
	xcube= pow(r,3,p)
	exposa=(p+1)>>2
	beta = pow(xcube+7, exposa, p)
	if (beta - recid) % 2 == 0:
		y = beta
	else:
		y = p - beta
	R = Point(r, y, order)
	# check R is on curve
	assert curve_256.contains_point(r,y)
	# checks that nR is at infinity
	assert order*R == INFINITY
	message=message.replace("\r\n","\n")
	lenmsg=len(message)
	#if lenmsg<253: lm = bytearray(struct.pack('B',lenmsg))
	#else: lm = bytearray(struct.pack('B',253)+struct.pack('<H',lenmsg)) # up to 65k
	#be = bytearray("\x18Bitcoin Signed Message:\n")+ lm + bytearray(message,'utf8')
	be = bytearray(message,'utf8')
	inv_r = inverse_mod(r,order)    
	e = int(dsha256( be ),16)
	# Q = (sR - eG) / r
	Q = inv_r * (  R.dual_mult( -e % order, s ) )
	# checks Q in range, Q on curve, Q order
	pubkey = Public_key( G, Q)
	addr = pub_hex_base58( pubkey.point.x(), pubkey.point.y(), compressed )
	# checks the address provided is the signing address
	if address != addr:
		raise Exception("Bad signature")
	# No need to check signature, since we don't have the public key
	# Public key is extracted from signature, verification will always return OK
	# We compute the pub key from the expected result of sig check.
	# Since Q =(sR-eG)/r  then  R == e/s*G + r/s*Q  is always true
	#pubkey.verifies( e, Signature(0,r,s) )
	

def decode_sig_msg(msg):
	msg=msg.replace("\r\n","\n")
	msglines=msg.split('\n')
	nline=len(msglines)
	i=1
	message=""
	while not msglines[i].startswith("---"):
		message=message+"\n"+msglines[i]
		i=i+1
	address=msglines[nline-3]
	if address=="": address=msglines[nline-4][9:]
	signature=msglines[nline-2]
	return address, signature, message[1:]

