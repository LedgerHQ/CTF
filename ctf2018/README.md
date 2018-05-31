# CTF 2018

All the details can be found here: https://www.ledger.fr/ctf2018
A blogpost giving the ranking and the solutions is available here: https://www.ledger.fr/2018/05/30/end-of-ctf-2018/

## Rules of the first stage: CTF

This qualification step consists in 3 different security & cryptography-related security challenges. Winners of the CTF qualifications will qualify for the second stage of the challenge and will be rewarded with one of the 13 special edition Ledger Nano S wallets. To qualify as a winner, participants need to be:

    Either the first participant to find a correct answer to one of the three challenges; or
    One of the 10 best ranked participants – with the following ranking system: each problem solved gives 1 point; players with the same number points are ranked according to the time spent.

## Submitting your answer:

To submit your answers, it’s very simple. You only have to send an email:

    to the following address ctf2018+<X>@ledger.fr
    As a subject CTF#<Y>
    As a message, a quick explanation on how you succeeded

Replacing <X> by your answer, <Y> by the number of the challenge you solved (1, 2,or 3). For instance if you solved the problem number 2 and your answer is 00112233445566778899AABBCCDDEEFF. You send an email at the following address: ctf2018+00112233445566778899AABBCCDDEEFF@ledger.fr . The object of your email will be CTF#2. And the content of your email will explain the main lines of your solution.  

# CTF challenges

## Challenge 1: The mathematics behind RSA

Using the standard notations for RSA:

    Two distinct prime numbers p and q
    Modulus: n=pq and phi=(p-1)*(q-1).
    Let e be the public exponent such e is prime with phi.
    Let d be the private exponent such e*d = 1 mod phi

Encryption process is denoted E(x) = x^e mod n Decryption process is denoted E(y) = y^d mod n For each possible e public exponent, there exists messages x such that E(x) = x. For instance, if we choose p = 13, q=37, So we have n = 481, phi = 432. Choosing e = 73, it turns that all the messages x are such E(x) = x !!! Here is the question: Given p = nextprime(1337) and q = nextprime(6982) phi = (p-1) * (q-1) Compute the product (Mod 1337694213377816) of all values of e for which the number of x such as E(x) = x is at minimum (1<e<phi, and gcd(e,phi) = 1)

    Send your answer in decimal format at this address ctf2018+<your_answer>@ledger.fr (without the ‘<‘ and ‘>’). The subject will be CTF#1, your message should explain quickly how you did it.

## Challenge 2: Access control

You’re given a program which runs on a remote host. This program implements an access control based on AES. You’re asked to find the input which outputs “**** Login Successful ****”. You’re not asked to modify the exec so that it outputs  “**** Login Successful ****” (it’s supposed to run on my machine). It’s compiled on Linux-64, and is not striped.

    Send your answer in hexadecimal format (lower case) at this address: ctf2018+<your_answer>@ledger.fr (without the ‘<‘ and ‘>’). The subject will be CTF#2, your message should explain quickly how you did it.

Download the file in CTF2/ctf2

## Challenge 3: $camcoin is the new Bitcoin

In order to solve scaling issue of Bitcoin, $camCoin Company developed its own coin: $camCoin. The overall system looks like Bitcoin except for the signature.

    The address format is the same as for Bitcoin
    The Key format is the same as for Bitcoin
    The Elliptic Curve is the same as for Bitcoin

Only two things change: 1. The transaction to sign becomes human readable: It’s formatted as a string containing the amount to send, the address from which it’s sent and the address to which it’s sent. For instance when Alice wants to send 42 $camCoins to Bob, she signs the following message: “Amount:42 From:1Ppecdv2jWjZjdSJjnQs5JaGhethCsdTCL To:1QFmDXuBr9QY5NoRdbYfZBFFP5cTS9rL4E” Where 1Ppecdv2jWjZjdSJjnQs5JaGhethCsdTCL is the address of Alice and 1QFmDXuBr9QY5NoRdbYfZBFFP5cTS9rL4E is the address of Bob. 2. In order to insert a timestamp of the transaction, the ECDSA signature, is performed using the epoch time of the transaction:

   - k = current time of the transaction (epoch format)
   - - <img src="https://latex.codecogs.com/gif.latex?O_t=\text { (i,j) = kG } t " /> 
   - - <img src="https://latex.codecogs.com/gif.latex?O_t=\text { x = i mod n } t " /> 
   - - <img src="https://latex.codecogs.com/gif.latex?O_t=\text { y = k^{-1} (H(m) + sw) mod n } t " /> 

The signature (x,y) is finally converted in base64 format. The Hash is computed directly on the message (no “Bitcoin Signed Message…” appended) using Sha256. Edit: the Hash is computed as Sha256(Sha256(data)) as for Bitcoin but without the “Bitcoin Signed message” string Here is an example with Alice wallet.

    Alice Private Key (WiF): 5JKpPhpoVaibqkFdwWzaPoQaHzNTCRmyjyqEpa67G8msKCiyiuA
    Alice $camCoin Address: 1Ppecdv2jWjZjdSJjnQs5JaGhethCsdTCL
    Bob $camCoin Address: 1QFmDXuBr9QY5NoRdbYfZBFFP5cTS9rL4E

The transaction to sign is: “Amount:42 From:1Ppecdv2jWjZjdSJjnQs5JaGhethCsdTCL To:1QFmDXuBr9QY5NoRdbYfZBFFP5cTS9rL4E” Hash of the message is (hexadecimal): 18e6d4da1887b0083350f188a29a3895c5755f0e86b84e95ba26eaee0ba9c38a The timestamp is: 1521543600 (Tuesday 20 March 2018 12:00:00 CET) Signature is: HKaLZ/jSgiehh7cyhP5A7AXfEEwuQudjJiJqQLn2qa6Rc9oH1uZ6LztNIFEnG1Lp4EJnNF/RhXgJcky28lD/j6U= Find in the following file (CTF3/transactions.txt) the list of Bob $camCoin transactions. Can you sign a transaction with 1000000 $camcoin to Eve’s address: 14pHuKrkRhLKsW6zxHKQ64DFGyKQffj7GW with the following timestamp: 1521543600 (Tuesday 20 March 2018 12:00:00 CET) ?

    Send your answer in base64 format at this address: ctf2018+<your_answer>@ledger.fr (without the ‘<‘ and ‘>’). The subject will be CTF#3, your message should explain quickly how you did it.

## Hardware Bounty
Get qualified

To get qualified, it’s simple, you will have to be among the 100 best ranked. Then we will send you one sample in one month (on the 20th of April). If ever you can solve the 3 challenges, you’ll be shipped as soon as you solve the 3 challenges!
A few more details

Qualified players will be able to participate to the second round of the challenge. The second round is a dedicated Hardware bounty: we’ll ship to each qualified players a sample of the hardware bounty containing 1.337 BTC! Retrieve the key & get the money – it’s as simple as that. More details on the Hardware bounty:

    Our hardware bounty is a simple USB token which computes Elliptic curves scalar multiplication signatures (secp256k1) using the private key of a Bitcoin wallet containing 1.337 BTC;
    The Hardware bounty is a specially modified Nano device. There is no PIN code and the hardware does not embed all the countermeasures of the Nano S; and
    The key is inside the hardware bounty application, an ECDSA signature is performed.

    Retrieve the key and get the money. Another prize from the CTF challenge: you’ll will be invited to a job interview at Ledger!
