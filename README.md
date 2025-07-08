# **Simple Router Implementation for LLM Startup Network**

A network simulation project implementing routing and firewall functionality for a Large Language Model (LLM) startup company. This project creates a multi-floor corporate network topology with specific security policies using Mininet for network emulation and POX controller for Software-Defined Networking (SDN). The implementation includes sophisticated traffic filtering between departments, trusted/untrusted external hosts, and critical server infrastructure.

## **Getting Started**

These instructions will give you a copy of the project up and running on your local machine for development and testing purposes. The project requires a virtual machine environment with Mininet and POX controller pre-installed for proper network simulation.

## **Prerequisites**

Requirements for the software and other tools to build, test and run the network simulation:

* **Virtual Machine** - Ubuntu-based VM with networking capabilities (VirtualBox, VMware, or similar)
* **Mininet** - Network emulator for creating virtual networks
* **POX Controller** - Python-based OpenFlow SDN controller
* **Python 2.7/3.x** - For controller development and mininet scripts
* **Wireshark** - For packet analysis and testing (optional but recommended)
* **OpenFlow** - Software-defined networking protocol support

## **Installing**

**Step 1: Set up your VM environment**
```bash
# Ensure your VM has mininet installed
sudo mn --version
```

**Step 2: Install POX controller (if not already installed)**
```bash
cd ~
git clone https://github.com/noxrepo/pox
cd pox
```

**Step 3: Download and place the project files**
```bash
# Download the provided starter code
wget https://users.soe.ucsc.edu/~qian/code/final_project.zip
unzip final_project.zip
```

**Step 4: Place files in correct directories**
```bash
# Copy controller to POX directory
cp final_controller_skel.py ~/pox/pox/misc/

# Copy topology file to home directory  
cp final.py ~/
```

**Step 5: Verify installation**
```bash
# Test mininet installation
sudo mn --test pingall
```
## **Running the tests**
**Step 1: Start the POX controller**
```bash
cd ~/pox
python pox.py misc.final_controller_skel
```

**Step 2: In a new terminal, run the mininet topology**
```bash
sudo python final.py
```

**Step 3: Test basic connectivity**
```bash
mininet> pingall
```

## **Sample Tests**

**Test ICMP blocking between departments**
```bash
mininet> h101 ping h201
# Should fail - Department A cannot ping Department B
```

**Test untrusted host restrictions**
```bash
mininet> h_untrust ping h_server  
# Should fail - Untrusted host blocked from server
```

**Test trusted host access**
```bash
mininet> h_trust ping h101
# Should succeed - Trusted host can reach Department A
```

## **Style test**

Checks if the OpenFlow rules are properly installed and traffic filtering works correctly:

```bash
# Check flow table entries
mininet> dpctl dump-flows

# Verify specific port forwarding vs flooding
# IP traffic should use specific ports, non-IP can flood
```

## **Deployment**

For deploying this network simulation in a production learning environment:
- Ensure adequate VM resources (minimum 2GB RAM, 20GB storage)
- Configure VM network adapter in NAT or Host-only mode
- Consider using multiple VMs for distributed testing scenarios
- Document any custom IP addressing schemes for your environment

## **Built With**

* **Mininet** - Network emulator for creating virtual networks
* **POX Controller** - Python-based OpenFlow controller framework  
* **OpenFlow Protocol** - Software-defined networking communication standard
* **Python** - Programming language for controller logic
* **Virtual Machine Technology** - Isolated environment for network simulation

## **Authors**

* **Violeta Solorio** - *Implementation and Testing* - violetxs16
* **Course Instructor** - *Starter Code*

