Author: George Zaytsev (groke)<br>
Seems like this server doesn't respect network byte order.<br>
It swaps byte order in some tcp header fields (sport, dport, ack, seq). Could you get the flag from it?<br>
**209.250.241.50:51966** (chall down)