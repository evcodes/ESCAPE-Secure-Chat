# ESCAPE-Secure-Chat
This is a secure chat application.

To generate the key for every user 
1. python gen_key.py 

This will generate everyone's private key in a password protected mode and a public key list in the SETUP directory. By running this, each user needs to type their password here.

To establish the session:

1. python netsim/network.py -a 'ABC' -c
2. python establish_session_listen.py -i A -a A -p (A's password)
3. python establish_session_listen.py -i A -a B -p (B's password)
4. python establish_session_listen.py -i A -a C -p (C's password)
5. python establish_session_initiate.py (initiator password, here is A's password)

Make that run 5 steps after all steps 2, 3, 4 saying that 'Main loop started'. So the all user wait for A to generate the shared key.



