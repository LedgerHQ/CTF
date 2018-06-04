#!/usr/bin/python2
# -*- coding: ascii -*-

# Ledger Capture The Flag 2018 Challenge 3
# Copyright (C) 2018  Antoine FERRON - BitLogiK


from ECDSA_BTC import *
from ECDSA_256k1 import *
load_gtable('G_Table')
import base64

# Check the validity of the example
msgAlice = "Amount:42 From:1Ppecdv2jWjZjdSJjnQs5JaGhethCsdTCL To:1QFmDXuBr9QY5NoRdbYfZBFFP5cTS9rL4E"
sigAlice = "HKaLZ/jSgiehh7cyhP5A7AXfEEwuQudjJiJqQLn2qa6Rc9oH1uZ6LztNIFEnG1Lp4EJnNF/RhXgJcky28lD/j6U="
bitcoin_verify_message("1Ppecdv2jWjZjdSJjnQs5JaGhethCsdTCL", sigAlice, msgAlice)

# Load transactions file
file = open("transactions.txt", "r")
txs = file.readlines()
file.close()
# Seek for 2 signatures with the same R = k.G
Rsigs = [x[:42] for x in txs[1::2]]
Rsame = [x for x in Rsigs if Rsigs.count(x) > 1][0]
Rsame_idx = [i for i, x in enumerate(Rsigs) if x == Rsame]
# Load these 2 txs
m1_idx = Rsame_idx[0]*2
m1 = txs[m1_idx][:-1].rstrip('\n')
sigi1 = txs[m1_idx+1].rstrip('\n')
m2_idx = Rsame_idx[1]*2
m2 = txs[m2_idx].rstrip('\n')
sigi2 = txs[m2_idx+1].rstrip('\n')
# Check proper loading
BoB_Adr_provided = "1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA"
bitcoin_verify_message(BoB_Adr_provided, sigi1, m1)
bitcoin_verify_message(BoB_Adr_provided, sigi2, m2)
# Get the private key from these 2 txs
BoB_pv = recoverk(m1,sigi1, m2, sigi2)
BoB_Adr = pvtoadr(BoB_pv, False)
print "Bob computed address :",BoB_Adr
# check the private key is the good one
assert BoB_Adr == BoB_Adr_provided
# sign the message
mbob = "Amount:1000000 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:14pHuKrkRhLKsW6zxHKQ64DFGyKQffj7GW"
privkey = Private_key( BoB_pv )
hm = int(hash_msg(mbob),16)
k = 1521543600
signature = privkey.sign( hm , k )
signature_str = bitcoin_encode_sig( signature )
signature64 = base64.b64encode( signature_str )
print "Signature of",mbob
print signature64
