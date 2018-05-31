import sys
from ECDSA_BTC import *
from ECDSA_256k1 import *
import base64
mAlice = "Amount:42 From:1Ppecdv2jWjZjdSJjnQs5JaGhethCsdTCL To:1QFmDXuBr9QY5NoRdbYfZBFFP5cTS9rL4E"
sAlice = "HKaLZ/jSgiehh7cyhP5A7AXfEEwuQudjJiJqQLn2qa6Rc9oH1uZ6LztNIFEnG1Lp4EJnNF/RhXgJcky28lD/j6U="
bitcoin_verify_message("1Ppecdv2jWjZjdSJjnQs5JaGhethCsdTCL", sAlice, mAlice)
m1 = "Amount:701245 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1Apd6spZhPx86oSuKMimv5K6aq69wGxsTY"
sigi1 = "G8ASwMQNxVKdQpUjwSGFYp+QA+fhUDMqc3fLIArLIG6jckTZab+KCxYt6NzYEStxfCRVh26PEoZ+semt4Kot6j4="
m2 = "Amount:760103 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:1BaU9W662GoBCwoPMFC76qgiCqRdW6K9Mu"
sigi2 = "G8ASwMQNxVKdQpUjwSGFYp+QA+fhUDMqc3fLIArLIG6jE9k34ZhAuDRCzn78Suf5j2uWTDytew3z2iathwdc4Wc="
bitcoin_verify_message("1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA", sigi1, m1)
bitcoin_verify_message("1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA", sigi2, m2)
BoB_pv = recoverk(m1,sigi1, m2, sigi2)
BoB_Adr = pvtoadr(BoB_pv, False)
print "Bob Address :"
print BoB_Adr
mbob = "Amount:1000000 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:14pHuKrkRhLKsW6zxHKQ64DFGyKQffj7GW"
privkey = Private_key( BoB_pv )
hm = int(hash_msg(mbob),16)
k = 1521543600
load_gtable('G_Table')
signature = privkey.sign( hm , k )
signature_str = bitcoin_encode_sig( signature )
signature64 = base64.b64encode( signature_str )
bitcoin_verify_message("1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA", signature64, mbob)
print "Signature of ",mbob
print signature64