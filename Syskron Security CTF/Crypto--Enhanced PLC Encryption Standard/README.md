Our IT department wants us to encrypt our PLC traffic. So we created our own encryption scheme, called the Enhanced PLC Encryption Standard.<br>
The idea is simple, and brilliant:<br>
&nbsp;&nbsp;&nbsp;&nbsp;1.Every PLC gets the shared secret password – this is so long, nobody can brute force it.<br>
&nbsp;&nbsp;&nbsp;&nbsp;2.If two devices want to communicate, one of them (A) sends a unique challenge to the other device (B).<br>
&nbsp;&nbsp;&nbsp;&nbsp;3.B gets the challenge, and hashes each character of the password with the challenge: response = hash(char + challenge).<br>
&nbsp;&nbsp;&nbsp;&nbsp;4.For security purposes, we use SHA-256 here (no insecure MD5 or SHA-1!). We also hash each character separately, so the full password can't be leaked if an attacker records the responses.<br>
&nbsp;&nbsp;&nbsp;&nbsp;5.B sends a lot of responses back to A. A knows the length of the password, and the password itself. So A can terminate the connection if responses are missing, or if there are too many responses.<br>
&nbsp;&nbsp;&nbsp;&nbsp;6.A also conducts hash(char + challenge), and compares every response. If there is any mismatch, A terminates the connection.<br>
&nbsp;&nbsp;&nbsp;&nbsp;7.If every response matches, A and B start to communicate using the shared secret password as the key. We use 3DES in CBC mode here, because our PLCs don't support military-grade AES.<br>
We sent a sample log to IT. For us, this looks clearly encrypted and secure. Our key is 24 bytes strong. One website says it takes 76 SEXTILLION YEARS to crack this.<br>
P.S. We didn't find a possibility to implement an IV, so it's 8 times 0.
