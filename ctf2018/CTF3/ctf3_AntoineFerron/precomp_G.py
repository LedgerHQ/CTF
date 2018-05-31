#! /usr/bin/env python
# coding=utf8

# Precompute G , FastSignVerify
# Copyright (C) 2014  Antoine FERRON

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>


# Generating precomputed table for G mult speed up


from ECDSA_256k1 import *

xG  =   0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
yG  =   0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L
orderG= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L

def mult16(pt):
    for i in xrange(4):
        pt=pt.double()
    return pt

def gen_table():
    G = Point( xG, yG, orderG )
    table = []
    nG=G
    for i in xrange(64):
        table.append( [ k*nG for k in range(1,16) ] )
        nG=mult16(nG)
    return table

if __name__ == '__main__' :
    import cPickle as pickle
    print "Generation of table"
    table=gen_table()
    with open('G_Table', 'wb') as output:
        pickle.dump(table, output, -1)
    print "done"
    print "Checking"
    #Checking table
    with open('G_Table', 'rb') as input:
        tableread = pickle.load(input)
    G = Point( xG, yG, orderG )
    c256k1 = CurveFp( 2**256-2**32-2**9-2**8-2**7-2**6-2**4-1 , 7 )
    for n in xrange(64):
        for k in range(1,16):
            p=tableread[n][k-1]
            assert c256k1.contains_point(p.x(),p.y())
            assert (k*16**n)*G == p
    print "Precomputed table OK"