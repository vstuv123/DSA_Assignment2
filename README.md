🧠 Network Monitoring and Analysis System (Linux Version)
👨‍💻 Author

Name: Muhammad Abdullah
Registration No: 476270
Course: Data Structures & Algorithms (Assignment 2)
Platform: Linux (Ubuntu 22.04 or later)

📘 Project Overview

The Network Monitoring and Analysis System is a C++ project designed to simulate the behavior of a basic network monitoring tool on Linux systems.
It automates core network operations — such as packet capturing, dissecting, filtering, and replaying — to emulate the functioning of tools like Wireshark at a simplified level.

This project demonstrates the application of core Data Structures and Algorithms (DSA) concepts — particularly stacks, queues, and linked lists — in a real-world networking context, such as analyzing and managing packet data flow.

🧩 Key Features

Packet Capture Simulation:
Generates mock network packets with random IPs, sizes, and timestamps.

Packet Dissection:
Implements a Stack (LIFO) data structure to dissect packets layer by layer (Ethernet → IP → TCP).

Packet Filtering:
Filters packets based on source and destination IP addresses.

Replay Simulation:
Uses a Queue (FIFO) to resend failed packets, including retry logic for transmission errors.

Thread Delays:
Adds realistic time delays to simulate actual network transmission.

Clean Terminal Output:
Displays real-time updates, status messages, and statistics during simulation.

⚙️ Data Structures Used
Data Structure	Usage
Stack (Custom Linked List)	Used for packet dissection (LIFO – reverse layer order)
Queue (Custom Linked List)	Used for packet replay (FIFO – resend in original order)
Vector	To store captured packets dynamically
Struct	To define packet structure (fields: id, timestamp, IPs, size, layers)
🧱 File Structure
Assignment2_DSA/
│
├── Task.cpp        # Main source code (Linux version)
├── README.md       # Project documentation (this file)
└── Task            # Executable generated after compilation

🧰 Prerequisites

Before running the program, ensure the following are installed on your Linux system:

Operating System: Ubuntu / Debian (22.04 or later recommended)

Compiler: g++ (C++17 or later)

Privileges: Root access (sudo required)

🧮 Compilation Instructions

To compile the program, open the terminal in the folder containing Task.cpp and run:

g++ Task.cpp -o Task -std=c++17 -pthread


This command compiles your C++ source file and generates an executable named Task.

▶️ Running the Program

Because this project simulates low-level network operations, it may require administrative privileges.

Run the program using:

sudo ./Task <network_interface>

Example:
sudo ./Task eth0


If you’re unsure about your network interface name, list all available interfaces with:

ip link show

🧪 Sample Output
===== Network Monitor Simulation (Linux) =====

Listening on interface: eth0
Captured Packet 1 (192.168.1.5 -> 8.8.8.8)
Captured Packet 2 (192.168.1.10 -> 1.1.1.1)

--- Packet Dissection ---
Layer: TCP
Layer: IPv4
Layer: Ethernet

--- Filtering Packets ---
Filtering packets from 192.168.1.5 to 8.8.8.8...
Filtered 2 packets.

--- Replay Simulation ---
Replaying Packet 1 ... Success
Replaying Packet 2 ... Failed, retrying...
Packet 2 Replay success after retry

Simulation Complete

🔁 Program Flow Summary

Packet Capture – Generates random packets using a custom data structure.

Dissection – Uses a Stack to print network layers in reverse order.

Filtering – Filters packets between specified source and destination IPs.

Replay Simulation – Queues filtered packets, handles retries for failed transmissions.

Completion – Prints a simulation summary in a clean terminal format.

🧮 Concepts Demonstrated

Application of Stacks and Queues using Linked Lists.

Use of Structs and Vectors for dynamic packet storage.

Simulation of real-world network flow using delays and retry logic.

Integration of Data Structures and Algorithms into system-level programming.

🧾 Conclusion

This project successfully demonstrates the practical use of Data Structures in network systems programming.
By utilizing stacks for layer dissection and queues for packet management, it bridges the gap between theoretical DSA concepts and their real-world applications in network monitoring and analysis.
