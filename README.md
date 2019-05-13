# ESCAPE-Secure-Chat
This is a secure chat application.

Firstly, application will set up the network by running: 

1. python netsim/network.py -p ./ -a ABC

This will create a network on the ./ directory and the address space for every user 

Then, to generate the key for every user:

1. python gen_key.py -l ABC

This will generate private key for everyone in the USER LIST in a password protected mode and a public key list in the SETUP directory. By running this, each user needs to type their password here.

To establish the session:

1. python establish_session_listen.py -i A -a A -p (A's password)
2. python establish_session_listen.py -i A -a B -p (B's password)
3. python establish_session_listen.py -i A -a C -p (C's password)
4. python establish_session_initiate.py -i A -p (initiator's password, here is A's) -l (ADDRES_SPACE)
5. python netsim/network.py -p ./ -a ABC -c clean

Make that run 4 steps after all steps 1,2,3 saying that 'Main loop started'. So the all users wait for initiator to generate the shared key. Step 5 will clean out the establish_session IN/OUT files when establishing the session. 

Now begin the Chat!

Since this is a group chat app, when a user sends message, it will be broadcast to other users. 

We want to have one person sending messages and the other n-1 people receiving the messages.

1. python netsim/sender.py -p ./ -a addr -k password
2. python netsim/receiver.py -p ./ -a receiver1 -k password
3. python netsim/receiver.py -p ./ -a receiver2 -k password

Then, the sender sends messages to the users.

If another user wants to send a communication, we must run:

python netsim/network.py -p ./ -a ABC -c clean
