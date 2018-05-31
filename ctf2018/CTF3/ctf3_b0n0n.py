#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import hashlib
import ecdsa
import base64
import time
import re
import sys
# https://github.com/shirriff/bitcoin-code/blob/master/keyUtils.py
import keyUtils


class Transaction(object):
    def __init__(self, from_, to, amount):
        self.timestamp = time.time()
        self.from_ = from_
        self.to = to
        self.amount = amount
        self._gen_tran()
        self._gen_msg_hash()

    def _gen_tran(self):
        tran_pattern = "Amount:{} From:{} To:{}"
        self.tran_raw = tran_pattern.format(self.amount, self.from_, self.to)

    def __str__(self):
        return self.tran_raw

    def _gen_msg_hash(self):
        self.msg_hash = hashlib.sha256(hashlib.sha256(self.tran_raw).digest()).digest()

    def gen_sig(self, priv_key, k=None):
        if k == None:
            k = self.timestamp
        sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
        sig = "\x1c"+sk.sign_digest(self.msg_hash, k=k)
        return sig

class Node(object):
    def __init__(self, WiF=None, priv_key=None):
        if WiF != None:
            self.priv_wif = WiF
            self._wif_to_priv()
            self._gen_addr()

            self.transactions = []
            return

        if priv_key != None:
            self.priv_key = priv_key
            self._priv_to_wif()
            self._gen_addr()

            self.transactions = []
            return

    def _priv_to_wif(self):
        if self.priv_key != None:
            self.priv_wif = keyUtils.privateKeyToWif(self.priv_key.encode('hex'))
        else:
            print("[!]Setup private key first")

    def _wif_to_priv(self):
        if self.priv_wif != None:
            self.priv_key = keyUtils.wifToPrivateKey(self.priv_wif).decode('hex')
        else:
            print("[!]Setup private key WiF first")

    def _gen_addr(self):
        self.addr = keyUtils.keyToAddr(self.priv_key.encode('hex'))

    def send_to(self, amount, reciever):
        self.transactions.append(Transaction(self.addr, reciever, amount))

    def gen_tx_sig(self, idx, k=None):
        if idx >= len(self.transactions):
            print("[!]transaction index out of bound")
            return
        tx = self.transactions[idx]
        return tx.gen_sig(self.priv_key, k)

class Cracker(object):
    def __init__(self, transactions):
        self.G = ecdsa.ecdsa.generator_secp256k1
        self.n = self.G.order()
        self.sig_trans = {}

        self.transactions = transactions
        sigs = map(lambda x: x[1], transactions)
        msgs = map(lambda x: x[0], transactions)
        sigs = map(lambda x: base64.b64decode(x)[1:], sigs)
        for idx, sig in enumerate(sigs):
            r, _ = ecdsa.util.sigdecode_string(sig, self.n)
            self.sig_trans[r] = transactions[idx]

    def crack(self, start, end):
        """
        https://github.com/warner/python-ecdsa/blob/6c8a70eb615d4cb85e37e8e054db910e8c62a5c6/src/ecdsa/ecdsa.py#L139
        gonna borrow some code here

        s => priv_key

        (x, y) = k*G

        r = x mod n
        s = k^-1(H(m) + r*priv) mod n
        (r, s)

        (s*k - H(m)) * r^-1 = priv mod n
        """
        n = self.n
        k = start
        G = (k % n) * self.G
        for i in xrange(start, end):
            done = (i - start)
            if done % 100 == 0:
                sys.stdout.write(".")
                sys.stdout.flush()
            if done % 10000 == 0:
                sys.stdout.write("\n{} left\n".format(end - start - done))
                sys.stdout.flush()
            r = G.x()
            if r in self.sig_trans:
                self.cracked_tran = self.sig_trans[r]
                self.cracked_k = k
                msg, sig = self.sig_trans[r]
                sig = base64.b64decode(sig)[1:]
                hash_ = int(hashlib.sha256(hashlib.sha256(msg).digest()).digest().encode('hex'), 16)
                r, s = ecdsa.util.sigdecode_string(sig, n)
                self.priv_key = ((s * k) - hash_) * ecdsa.numbertheory.inverse_mod(r, n) % n
                self.priv_key = ("%x" % self.priv_key).decode('hex')
                print("[!]Found private key: {}".format(self.priv_key.encode('hex')))
                print("[!]k: {}".format(k))
                return

            G = G + self.G
            k += 1

    def cracked_key(self):
        if self.priv_key != None:
            return self.priv_key
        else:
            print("[!]No cracked private key")

    def verify(self):
        msg, sig = self.cracked_tran
        pattern = "Amount:(\d+) From:([0-9a-zA-Z]+) To:([0-9a-zA-Z]+)"
        amount, from_, to_ = re.match(pattern, msg).groups()
        txn = Transaction(from_, to_, amount)
        assert txn.gen_sig(self.priv_key, self.cracked_k).encode('hex') == base64.b64decode(sig).encode('hex')

def test():
    """
    Alice Private Key (WiF): 5JKpPhpoVaibqkFdwWzaPoQaHzNTCRmyjyqEpa67G8msKCiyiuA
    Alice $camCoin Address: 1Ppecdv2jWjZjdSJjnQs5JaGhethCsdTCL
    Bob $camCoin Address: 1QFmDXuBr9QY5NoRdbYfZBFFP5cTS9rL4E
    The transaction to sign is: “Amount:42 From:1Ppecdv2jWjZjdSJjnQs5JaGhethCsdTCL To:1QFmDXuBr9QY5NoRdbYfZBFFP5cTS9rL4E”
    Hash of the message is (hexadecimal): 18e6d4da1887b0083350f188a29a3895c5755f0e86b84e95ba26eaee0ba9c38a
    The timestamp is: 1521543600 (Tuesday 20 March 2018 12:00:00 CET)
    Signature is: HKaLZ/jSgiehh7cyhP5A7AXfEEwuQudjJiJqQLn2qa6Rc9oH1uZ6LztNIFEnG1Lp4EJnNF/RhXgJcky28lD/j6U=
    """
    Alice_WiF = "5JKpPhpoVaibqkFdwWzaPoQaHzNTCRmyjyqEpa67G8msKCiyiuA"
    Alice = Node(WiF = Alice_WiF)
    assert Alice.addr == "1Ppecdv2jWjZjdSJjnQs5JaGhethCsdTCL"
    Bob_addr = "1QFmDXuBr9QY5NoRdbYfZBFFP5cTS9rL4E"
    Alice.send_to(42, Bob_addr)
    tx  = Alice.transactions[0]
    assert str(tx) == \
        "Amount:42 From:1Ppecdv2jWjZjdSJjnQs5JaGhethCsdTCL To:1QFmDXuBr9QY5NoRdbYfZBFFP5cTS9rL4E"

    assert tx.msg_hash.encode('hex') == "18e6d4da1887b0083350f188a29a3895c5755f0e86b84e95ba26eaee0ba9c38a"

    assert base64.b64encode(Alice.gen_tx_sig(0, 1521543600)) == \
        "HKaLZ/jSgiehh7cyhP5A7AXfEEwuQudjJiJqQLn2qa6Rc9oH1uZ6LztNIFEnG1Lp4EJnNF/RhXgJcky28lD/j6U="

def solve():
    """
    bf possible ks, compare the r to get the private key
    """
    transactions = []
    with open("transactions.txt", "rb") as f:
        lines = f.readlines()
    for i in xrange(0, len(lines), 2):
        transactions.append((lines[i].strip(), lines[i+1].strip()))

    test_tran = [("Amount:42 From:1Ppecdv2jWjZjdSJjnQs5JaGhethCsdTCL To:1QFmDXuBr9QY5NoRdbYfZBFFP5cTS9rL4E",
                 "HKaLZ/jSgiehh7cyhP5A7AXfEEwuQudjJiJqQLn2qa6Rc9oH1uZ6LztNIFEnG1Lp4EJnNF/RhXgJcky28lD/j6U=")]

    # transactions.extend(test_tran)
    # start = 1521543600 - 3600*24*365

    """
    [!]Found private key: 5014b573432161171a4c8312f67abe5cfe79d83382c1fea1dfb2c9c268216bab
    [!]k: 1490296852
    [!]Found private key: 5014b573432161171a4c8312f67abe5cfe79d83382c1fea1dfb2c9c268216bab
    [!]k: 1490607556
    """
    start = 1490607556-1
    end = 1490607556+1
    cracker = Cracker(transactions)
    cracker.crack(start, end)
    key = cracker.cracked_key()
    cracker.verify()

    """
    Can you sign a transaction with 1000000 $camcoin to Eve’s address: 14pHuKrkRhLKsW6zxHKQ64DFGyKQffj7GW with the following timestamp: 1521543600 (Tuesday 20 March 2018 12:00:00 CET) ?
    """
    Bob = Node(priv_key=key)
    Bob.send_to(1000000, "14pHuKrkRhLKsW6zxHKQ64DFGyKQffj7GW")
    print "="*80
    print Bob.transactions[0]
    print base64.b64encode(Bob.gen_tx_sig(0, 1521543600))
    print "="*80

    """
    Send your answer in base64 format at this address: ctf2018+<your_answer>@ledger.fr (without the ‘<‘ and ‘>’). The subject will be CTF#3, your message should explain quickly how you did it.

    """
    print "email: ctf2018+{}@ledger.fr".format(base64.b64encode(Bob.gen_tx_sig(0, 1521543600)))

# test()
solve()
# calc_priv(1521543600, base64.b64decode("HKaLZ/jSgiehh7cyhP5A7AXfEEwuQudjJiJqQLn2qa6Rc9oH1uZ6LztNIFEnG1Lp4EJnNF/RhXgJcky28lD/j6U="))
