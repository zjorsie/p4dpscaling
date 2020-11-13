# p4dpscaling
Controller application for a P4 network, which uses GRPC to control the switches. 


# Usage:

First, make a Mininet network. For example, spin up a default network using my docker implementation of the logging switch and the non-logging simple_switch targets.

The switches require both GRPC and Apache Thrift support (since ingress-ingress cloning is not supported by the simple_switch). Therefore, P4 mirror_sessions are used to mimic this behaviour.

Currently, the docker network needs to be restarted after the controller has connected to them. The controller will connect a next time, but the switch will not send digests to the controller.



    usage: mycontroller.py [-h] [-p4 P4] [-p4folder P4FOLDER] [-p4file P4FILE]
                        [-wb] [--scale] [--cpsync]

    optional arguments:
    -h, --help          show this help message and exit
    -p4 P4              P4 version for network program
    -p4folder P4FOLDER  Folder where p4 program is located
    -p4file P4FILE      P4 file for compilation
    -wb, --with-build   Build all p4 programs
    --scale             Do scaling experiment
    --cpsync, -cps      Do synchronization over the control plane


# Normal usage for data-plane migration:
    ./mycontroller.py -p4folder p4source-dpsync/ --scale --with-build

# Normal usage for control plane migration:
    ./mycontroller.py -p4folder p4source-cpsync/ --scale --with-build --cpsync


# logging: