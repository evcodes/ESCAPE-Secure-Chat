# ESCAPE-Secure-Chat
This is a secure chat application.

To generate the key for every user 
1. python gen_key.py 
This will generate everyone's private key in a password protected mode and a public key list in the SETUP directory.

To establish the session:

1. python netsim/network.py -a 'ABC' -c
2. python establish_session_listen.py -i A -a A -p this_is_A
3. python establish_session_listen.py -i A -a B -p this_is_B
4. python establish_session_listen.py -i A -a C -p this_is_B
5. python establish_session_initiate.py

Make that run 5 steps after all steps 2, 3, 4 saying that 'Main loop started'. So the all user wait for A to generate the shared key.



