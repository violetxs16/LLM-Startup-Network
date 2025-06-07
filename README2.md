Violeta Solorio
Student ID: 2081590
CSE 150
Lab 4 - Final project

Files submitted:

1. final_skel.py
2. finalcontroller_skel.py
3. project.pdf
4. README.txt


Further file explanation:

1. final_skel.py
    1. The final_skel.py is a python file that contains the network topology of the simple IPv4 Router. Here is the structure of the file
        1. First the switches are created
            1. core represents core switch
            2. f1s1 represents floor 1 switch 1
            3. f1s3 represents floor 1 switch 3
            4. etc.
        2. Next to keep the code clean, I created the links from the switches to the core as seen in the picture of the topology.
        3. Next, all the hosts are created in the following order
            1. direct connect hosts to core
            2. floor 1 hosts
            3. floor 2 hosts
        4.Lastly, the links between the hosts and the switches are established
2. finalcontroller_skel.py
    1. The finalcontroller_skel.py file contains the root logic that will be utilized by the router. The logic in a general view does the following:
        - Untrusted Host cannot send ICMP to Host 101-104, 201-204, or the LLM Server.
        - Untrusted Host cannot send any IP traffic to the LLM Server.
        - Trusted Host cannot send ICMP traffic to Host 201-204 in Department B, or the LLM
        Server.
        - Trusted Host cannot send any IP traffic to the LLM Server.
        - Hosts in Department A (Host 101-104) cannot send any ICMP traffic to the hosts in
        Department B (Host 201-204), and vice versa
    2. Two extra helper functions where created to help aid in the process of handling a packet and establishing an entry in the fowarding table for the core switch. 
    3. The core switch handles all the logic of wether or not a packet should continue to be fowarded or be dropped
    4. The other switches are simply in charge of fowarding and do not contain any logic for dropping a packet. 