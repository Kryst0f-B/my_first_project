# stacked_windows

import os
import sys
import subprocess
from pathlib import Path
import threading
import time
import ipaddress
from sys import stdout, stderr
from PyQt5.QtWidgets import (QApplication, QWidget, QStackedWidget, QPushButton,
                             QLabel, QLineEdit, QVBoxLayout, QHBoxLayout, QGridLayout,
                         QCheckBox, QRadioButton, QMessageBox, QButtonGroup, QLayout, QScrollArea)
from PyQt5.QtCore import Qt, QTimer, QObjectCleanupHandler

from network_hacking import krystof_changed_arp_mitm as arp_mitm
from network_hacking import tcp_syn_flood
from hash_cracking import cracking_algorithm_dict


"""Main window for selecting type of attack"""


class MainWindow(QWidget):
    def __init__(self):
        #GUI objects initialization
        super().__init__()
        self.hash_cracking_btn = QPushButton("Hash Cracking", self)
        self.malware_btn = QPushButton("Malware", self)
        self.network_btn = QPushButton("Network Hacking", self)
        self.select_btn = QPushButton("Select Option", self)
        self.info_btn = QPushButton("Information", self)
        self.message_box = QMessageBox(self)
        self.selected_value = None
        self.initUI()

    #GUI graphical appearance setup with CSS styling
    def initUI(self):
        self.setWindowTitle("Hacking toolbox")
        self.select_btn.setObjectName("select_btn")
        self.info_btn.setObjectName("info_btn")
        self.setStyleSheet("""
            QPushButton#select_btn{
                font-weight: Bold;
                margin: 20px;
            }
            QPushButton#info_btn{
                font-size: 25px;
                font-weight: Bold;
            }
            QPushButton{
                font-size: 40px;
                font-family: Times New Roman;
                padding: 25px 15px;
                margin: 10px;
                background-color: hsl(0, 0%, 89%);
            }
            QPushButton:hover{
                background-color: hsl(0, 0%, 70%);
            }
        """)
        #window layout setup
        h_box = QHBoxLayout()
        h_box.addWidget(self.hash_cracking_btn)
        h_box.addWidget(self.malware_btn)
        h_box.addWidget(self.network_btn)

        v_box = QVBoxLayout()
        v_box.addLayout(h_box)
        v_box.addWidget(self.select_btn)
        v_box.addWidget(self.info_btn, alignment=Qt.AlignRight)

        self.setLayout(v_box)

        self.hash_cracking_btn.clicked.connect(self.storing_value)
        self.network_btn.clicked.connect(self.storing_value)
        self.malware_btn.clicked.connect(self.storing_value)
        self.select_btn.clicked.connect(self.select_hack)
        self.info_btn.clicked.connect(lambda: self.show_message("Kryštof Budiš\nMaturitní práce 2024/25\nGymnázium Ústí nad Orlicí","Program Info"))

    #Pop-up message box with information for the user
    def show_message(self, message, title):
        self.message_box.setWindowTitle(title)
        self.message_box.setText(message)
        self.message_box.setStyleSheet("""
                    QMessageBox QLabel{
                        font-size: 17px;
                        font-weight: 500;
                    }
                    QMessageBox QPushButton{
                        font-size: 15px;
                        padding: 8px 12px;
                    }
                """)

        for button in self.message_box.buttons():
            self.message_box.removeButton(button)

        ok_button = self.message_box.addButton("Ok", QMessageBox.AcceptRole)
        close_button = self.message_box.addButton("Close", QMessageBox.RejectRole)

        #confirming users acknowledgement of possible consequences
        #if the user clicks cancel button he's sent back to main window
        if self.selected_value == "Malware":
            self.message_box.setIcon(QMessageBox.Warning)
            response = self.message_box.exec_()

            if self.message_box.clickedButton() == close_button:
                self.parent().setCurrentIndex(0)

        elif self.selected_value == "Network Hacking":
            self.message_box.setIcon(QMessageBox.Warning)
            response = self.message_box.exec_()

            if self.message_box.clickedButton() == close_button:
                self.parent().setCurrentIndex(0)

        else:
            self.message_box.setIcon(QMessageBox.Information)
            self.message_box.removeButton(close_button)
            response = self.message_box.exec_()

    #saves value for determining attack type
    def storing_value(self):
        self.hash_cracking_btn.setStyleSheet("background-color: hsl(0, 0%, 89%)")
        self.malware_btn.setStyleSheet("background-color: hsl(0, 0%, 89%)")
        self.network_btn.setStyleSheet("background-color: hsl(0, 0%, 89%)")
        if self.sender() == self.hash_cracking_btn:
            self.hash_cracking_btn.setStyleSheet("background-color: hsl(0, 0%, 29%);")
            self.selected_value = "Hash Cracking"
        elif self.sender() == self.malware_btn:
            self.malware_btn.setStyleSheet("background-color: hsl(0, 0%, 29%);")
            self.selected_value = "Malware"
        elif self.sender() == self.network_btn:
            self.network_btn.setStyleSheet("background-color: hsl(0, 0%, 29%);")
            self.selected_value = "Network Hacking"

    #opens a window for selected attack type
    def select_hack(self):
        if self.selected_value == "Hash Cracking":
            self.parent().setCurrentIndex(1)

        elif self.selected_value == "Malware":
            self.parent().setCurrentIndex(2)
            self.show_message("WARNING!!!\nMalware functionality is for educational and authorized use only\nUnauthorized use can lead to severe legal consequences\nAlways make sure to have explicit permission to use this tool", "Warning")

        elif self.selected_value == "Network Hacking":
            self.parent().setCurrentIndex(3)
            self.show_message("WARNING!!!\nNetwork hacking functionality is for educational and authorized use only\nUnauthorised use can lead to severe legal consequences\nAlways make sure to have explicit permission to use this tool", "Warning")

        else:
            self.show_message("You have not selected anything!", "information")


"""Window for malware. It doesn't work directly
from window, but instead opens repository where
the malware is stored so the user can transfer
it into a device through which he deploys it"""


class MalwareWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.label1 = QLabel("Malware functionality doesn't work directly from GUI\n\nYou need to open the directory where it is stored and manually\ntransfer it to target device")
        self.label2 = QLabel("To open malware directory click Go to dir button:")
        self.exec_btn = QPushButton("Go to dir", self)
        self.back_btn = QPushButton("Back", self)
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Malware")
        self.exec_btn.setObjectName("exec_btn")
        self.back_btn.setObjectName("back_btn")
        self.setStyleSheet("""
            QPushButton#exec_btn{
                font-weight: Bold;
                font-size: 30px;
            }
            QPushButton#back_btn{
                font-size: 25px;
            }
            QPushButton{
                width: 250px;
                height: 80px;
            }
            QPushButton:hover{
                background-color: hsl(0, 0%, 70%);
            }
            QLabel{
                font-size: 25px;
                font-weight: Bold;
            }
        """)

        v_box = QVBoxLayout()
        v_box.addWidget(self.label1)
        v_box.addWidget(self.label2)
        v_box.addWidget(self.exec_btn)
        v_box.addWidget(self.back_btn)

        self.setLayout(v_box)

        self.exec_btn.clicked.connect(self.get_dir)
        self.back_btn.clicked.connect(lambda: self.parent().setCurrentIndex(0))

    #differentiates between Windows and Linux system and accordingly opens the malware directory
    def get_dir(self):
        cwd = os.getcwd()

        if sys.platform == "win32":
            full_path = cwd + "\\usb_scripts"
            os.startfile(full_path)
        else:
            full_path = cwd + "/usb_scripts"
            subprocess.Popen(["xdg-open", full_path])


"""Window with network hacking options.
Has two types of attack: basic TCP/IP
SYN DOS attack and ARP poisoning that I
found on GitHub, but changed for my project."""


class NetworkHacks(QWidget):
    def __init__(self):
        super().__init__()
        self.main_window = MainWindow()
        self.label1 = QLabel("Network hacks:", self)
        self.dos_btn = QPushButton("DoS attack", self)
        self.arp_btn = QPushButton("ARP poisoning", self)
        self.exec_btn = QPushButton("Execute", self)
        self.back_btn = QPushButton("Back", self)
        self.attack_layout = QVBoxLayout()
        self.selected_value = None
        self.arp_thread = None
        self.sniffer_thread = None
        self.stop_event = threading.Event()
        self.radio_group = QButtonGroup()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Network hacking")
        self.exec_btn.setObjectName("exec_btn")
        self.back_btn.setObjectName("back_btn")
        self.label1.setObjectName("label1")
        self.setStyleSheet("""
            QPushButton#exec_btn{
                font-weight: Bold;
            }
            QPushButton#back_btn{
                font-size: 25px;
            }
            QPushButton{
                font-size: 30px;
                font-family: Times New Roman;
                margin: 5px;
                padding: 10px 25px;
                background-color: hsl(0, 0%, 89%);
            }
            QPushButton:hover{
                background-color: hsl(0, 0%, 70%);
            }
            QLineEdit{
                font-size: 30px;
            }
            QLabel#label1{
                font-size: 40px;
                font-weight: 350;
                font-family: Times New Roman;
            }    
            QLabel#label6{
                font-weight: Bold;
            }
            QLabel{
                font-size: 25px;
                font-weight: 400;
                font-family: Arial;
            }
        """)

        h_box = QHBoxLayout()
        h_box.addWidget(self.dos_btn, alignment=Qt.AlignTop)
        h_box.addWidget(self.arp_btn, alignment=Qt.AlignTop)

        v_box = QVBoxLayout()
        v_box.addWidget(self.label1, alignment=Qt.AlignTop)
        v_box.addLayout(h_box)
        v_box.addLayout(self.attack_layout)
        v_box.addWidget(self.exec_btn)
        v_box.addWidget(self.back_btn, alignment=Qt.AlignLeft)

        self.setLayout(v_box)

        self.back_btn.clicked.connect(self.reset_window)
        self.dos_btn.clicked.connect(self.select_value)
        self.arp_btn.clicked.connect(self.select_value)
        self.exec_btn.clicked.connect(self.select_attack)

    #diferentietes the type of attack and stores the value
    def select_value(self):
        self.arp_btn.setStyleSheet("background-color: hsl(0, 0%, 89%);")
        self.dos_btn.setStyleSheet("background-color: hsl(0, 0%, 89%);")
        if self.sender() == self.dos_btn:
            self.dos_btn.setStyleSheet("background-color: hsl(0, 0%, 29%);")
            self.selected_value = "Dos Attack"
            self.dos_layout()
        elif self.sender() == self.arp_btn:
            self.arp_btn.setStyleSheet("background-color: hsl(0, 0%, 29%);")
            self.selected_value = "Arp MITM"
            self.arp_layout()

    #after selecting attack this function executes it
    def select_attack(self):
        if self.selected_value == "Arp MITM":
            self.arp_mitm_attack()
        elif self.selected_value == "Dos Attack":
            self.syn_flood()
        else:
            self.main_window.show_message(message="You didn't select anything", title="Information")

    #dynamicly creates layout for ARP poisoning
    def arp_layout(self):
        self.layout_cleaner(self.attack_layout)
        self.label2 = QLabel("Select an IP range of target system:", self)
        self.label6 = QLabel("", self)
        self.ip_range_tb = QLineEdit(self)
        self.ip_range_tb.setPlaceholderText("e.g. 10.0.0.1/24")

        self.label6.setStyleSheet("font-weight: Bold;")

        self.attack_layout.addWidget(self.label2)
        self.attack_layout.addWidget(self.ip_range_tb)
        self.attack_layout.addWidget(self.label6)

    #dynamicly creates layout for DOS attack
    def dos_layout(self):
        self.layout_cleaner(self.attack_layout)
        self.label3 = QLabel("", self)
        self.label4 = QLabel("Enter IP address of the target:", self)
        self.label5 = QLabel("Enter a number of threads to use:", self )
        self.ip_add_tb = QLineEdit(self)
        self.threads_tb = QLineEdit(self)
        self.threads_tb.setPlaceholderText("e.g. 10 (used if not selected)")

        self.label3.setStyleSheet("font-weight: Bold;")

        self.attack_layout.addWidget(self.label3)
        self.attack_layout.addWidget(self.label4)
        self.attack_layout.addWidget(self.ip_add_tb)
        self.attack_layout.addWidget(self.label5)
        self.attack_layout.addWidget(self.threads_tb)

    #cleans the dynamic layout so another one can be selected
    def layout_cleaner(self, layout):
            while layout.count() > 0:
                item = layout.takeAt(0)
                if item:
                    if item.widget():
                        item.widget().deleteLater()
                    elif item.layout():
                        self.layout_cleaner(item.layout())


    """Part of code responsible for ARP MITM attack.
    I mostly used script from David Bombal, that I
    found on GitHub. I also made some upgrades and
    changes for it to suit my particular project"""

    #dynamically adds buttons (targets) that the user can attack
    def show_devices(self, devices):
        #prevents deformation of the window when scanning huge networks
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)

        grid = QGridLayout()

        self.layout_cleaner(grid)
        self.radio_group = QButtonGroup()
        self.select_btn = QPushButton("Select", self)

        i = 0
        x = 0

        #devides the targets into two columns of the same length
        if len(devices)%2 == 1:
            line = (len(devices) + 1)/2
        else:
            line = len(devices)/2

        for response in devices:
            ip = response["ip"]
            mac = response["mac"]

            radio_btn = QRadioButton(f"IP: {ip} | MAC: {mac}")
            radio_btn.setProperty("ip", ip)
            radio_btn.setProperty("mac", mac)

            #creates button for every target and assign the correct coordinates in the grid
            grid.addWidget(radio_btn, i, x)
            self.radio_group.addButton(radio_btn)

            i += 1
            if i == line:
                x += 1
                i = 0

        self.attack_layout.addLayout(grid)
        self.attack_layout.addWidget(self.select_btn)

    #when user presses esc key it ends the attack
    #works for DOS and ARP
    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape and self.selected_value == "Arp MITM":
            self.stop_event.set()
            if self.sniffer_thread and self.sniffer_thread.is_alive():
                self.sniffer_thread.join()
            if self.arp_thread and self.arp_thread.is_alive():
                self.arp_thread.join()
            self.label6.setText("Attack stopped")
        elif event.key() == Qt.Key_Escape and self.selected_value == "Dos Attack":
            tcp_syn_flood.stop_attack()
            self.label3.setText("Attack stopped")
        else:
            super().keyPressEvent(event)

    def arp_mitm_attack(self):
        working_dir = Path().resolve()

        ip = self.ip_range_tb.text().strip()

        #checks if correct IP format was entered
        if ip == "":
            self.label6.setText("You didn't enter IP address")
            return
        else:
            try:
                ipaddress.ip_network(ip, strict=False)
            except Exception as e:
                self.label6.setText(f"Error:\n{e}")
                return

        self.label6.setText("Scanning network...")
        QApplication.processEvents()
        #scans the whole network by arp scan
        try:
            arp_response = arp_mitm.arp_scan(ip)
        except Exception as e:
            self.label6.setText(f"Error:\n{e}")
            return

        if len(arp_response) == 0:
            self.label6.setText("Error:\nNo devices found")
            return

        arp_mitm.allow_ip_forwarding()

        gateway_list = arp_mitm.gateway_info(arp_response)
        gateway = gateway_list[0]

        available_devices = arp_mitm.clients(arp_res=arp_response, gateway_list=gateway_list)
        if len(available_devices) == 0:
            self.label6.setText("Error:\nNo devices found")
            return

        self.label6.setText("Select a device you want to attack:")
        self.show_devices(available_devices)

        self.select_btn.clicked.connect(lambda: self.confirm_selection(gateway, working_dir))

    #gives user info on the selected target
    #calls functions which execute the attack
    def confirm_selection(self, gateway, current_dir):
        selected_button = self.radio_group.checkedButton()
        if selected_button:
            ip = selected_button.property("ip")
            mac = selected_button.property("mac")
            self.label6.setText(f"Attacking device: IP: {ip} | MAC: {mac}")
            device_info = {"ip": ip, "mac": mac}

            #ensuring that stop event is cleared so the attack can run
            self.stop_event.clear()

            #this thread continuously sends spoof packets until the attack is stopped
            self.arp_thread = threading.Thread(target=self.send_spoof_packets, args=(gateway, device_info), daemon=True)
            self.arp_thread.start()

            os.chdir(current_dir)

            #this thread sniffs the data traffic between target and gateway
            self.sniffer_thread = threading.Thread(target=arp_mitm.packet_sniffer, args=(self.stop_event, [gateway["iface"]]), daemon=True)
            self.sniffer_thread.start()

    #sends packets to continuously spoof the target and gateway
    def send_spoof_packets(self, gateway, device_to_spoof):
            while not self.stop_event.is_set():
                try:
                    arp_mitm.arp_spoofer(gateway["ip"], gateway["mac"], device_to_spoof["ip"])
                    arp_mitm.arp_spoofer(device_to_spoof["ip"], device_to_spoof["mac"], gateway["ip"])
                    time.sleep(3)
                except Exception as e:
                    self.main_window.show_message(message=f"An error {e} in ARP spoofing occurred", title="Error")

    #resets the window when returning to main window
    def reset_window(self):
        self.layout_cleaner(self.attack_layout)
        self.selected_value = None
        self.stop_attack = None
        self.radio_group = None
        self.dos_btn.setStyleSheet("background-color: hsl(0, 0%, 89%);")
        self.arp_btn.setStyleSheet("background-color: hsl(0, 0%, 89%);")
        self.parent().setCurrentIndex(0)


    """Part of code responsible for DOS attack.
    For this attack I Linux hping3 application
    with carefully crafted TCP/IP SYN packet.
    """


    def syn_flood(self):
        #gets ip of target and number of threads to use
        router_ip = self.ip_add_tb.text().strip()
        num_threads = self.threads_tb.text().strip()

        #default thread value used if user leaves it empty
        if num_threads == "":
            num_threads = 10
        else:
            try:
                num_threads = int(num_threads)
            except Exception as e:
                self.main_window.show_message(f"Error {e}", "Warning")
                return

        #checks if the IP format is correct
        if router_ip == "":
            self.main_window.show_message("You didn't enter IP address", "Warning")
            return
        else:
            try:
                ipaddress.ip_address(router_ip)
            except Exception as e:
                self.main_window.show_message(f"Error {e}", "Warning")
                return

        self.label3.setText("Sending packets...")
        QApplication.processEvents()
        tcp_syn_flood.run_threads(router_ip, num_threads)


"""Window for hash cracking options.
I used dictionary type attack with
password list from GitHub"""


class HashCracking(QWidget):
    def __init__(self):
        super().__init__()
        self.sha1_button = QRadioButton("SHA1", self)
        self.sha256_button = QRadioButton("SHA256", self)
        self.ntlm_button = QRadioButton("NTLM", self)
        self.md5_button = QRadioButton("MD5", self)
        self.hash_input = QLineEdit(self)
        self.crack_button = QPushButton("Crack", self)
        self.label1 = QLabel("Select hashing algorithm:", self)
        self.label2 = QLabel("Enter a hash to decrypt:", self)
        self.result_label = QLabel("", self)
        self.back_btn = QPushButton("Back", self)
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Hash Cracking")
        self.crack_button.setObjectName("crack_button")
        self.back_btn.setObjectName("back_btn")
        self.result_label.setObjectName("result_label")
        self.setStyleSheet("""
            QPushButton#crack_button{
                font-weight: Bold;
            }
            QPushButton#back_btn{
                font-size: 25px;
            }
            QPushButton{
                font-size: 30px;
                font-family: Times New Roman;
                padding: 10px 25px;
                margin: 10px;
                background-color: hsl(0, 0%, 89%);
            }
            QPushButton:hover{
                background-color: hsl(0, 0%, 70%);
            }
            QRadioButton{
                font-family: Arial;
                font-size: 40px;
                padding: 30px;
            }
            QLabel#result_label{
                font-weight: Bold;
            }
            QLabel{
                font-size: 35px;
                font-weight: 350;
                font-family: Times New Roman;
                margin: 10px;
            }
            QLineEdit{
                font-size: 40px;
                font-family: Arial;
            }
        """)

        h_box = QHBoxLayout()
        h_box.addWidget(self.label2)
        h_box.addWidget(self.hash_input)

        grid = QGridLayout()
        grid.addWidget(self.sha1_button, 0, 0)
        grid.addWidget(self.sha256_button, 0, 1)
        grid.addWidget(self.ntlm_button, 1, 0)
        grid.addWidget(self.md5_button,1, 1)

        v_box = QVBoxLayout()
        v_box.addWidget(self.label1)
        v_box.addLayout(grid)
        v_box.addLayout(h_box)
        v_box.addWidget(self.result_label)
        v_box.addWidget(self.crack_button)
        v_box.addWidget(self.back_btn, alignment=Qt.AlignLeft)

        self.setLayout(v_box)

        grid.setAlignment(Qt.AlignCenter)
        self.result_label.setAlignment(Qt.AlignCenter)

        self.crack_button.clicked.connect(self.decryption)
        self.back_btn.clicked.connect(lambda: self.parent().setCurrentIndex(0))

    #takes user input and compares it to hash values of words from the password list
    def decryption(self):
        cleaned_hash = self.hash_input.text().replace(" ","").lower()

        #user can select from four different hash algorithms
        if self.sha1_button.isChecked():
            if len(cleaned_hash) == 40:
                password_status = cracking_algorithm_dict.main(cleaned_hash, "sha1")
                self.result_label.setText(password_status)
            else:
                self.result_label.setText("Invalid hash length")

        elif self.sha256_button.isChecked():
            if len(cleaned_hash) == 64:
                password_status = cracking_algorithm_dict.main(cleaned_hash, "sha_256")
                self.result_label.setText(password_status)
            else:
                self.result_label.setText("Invalid hash length")

        elif self.ntlm_button.isChecked():
            if len(cleaned_hash) == 32:
                password_status = cracking_algorithm_dict.main(cleaned_hash, "ntlm")
                self.result_label.setText(password_status)
            else:
                self.result_label.setText("Invalid hash length")

        elif self.md5_button.isChecked():
            if len(cleaned_hash) == 32:
                password_status = cracking_algorithm_dict.main(cleaned_hash, "md5")
                self.result_label.setText(password_status)
            else:
                self.result_label.setText("Invalid hash length")

        else:
            self.result_label.setText("You must select algorithm DUMBASS!")


"""Manager of all the windows in my
program. This class controls them and
allows them to be managed in single
window by the stacked QStackedWidget"""


class App(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Penetration testing toolkit")

        self.main_window = MainWindow()
        self.malware_window = MalwareWindow()
        self.network_window = NetworkHacks()
        self.hash_cracking = HashCracking()

        self.main_window.setMaximumSize(1000,1000)
        self.malware_window.setMaximumSize(1000, 1000)
        self.network_window.setMaximumSize(1000, 1000)
        self.hash_cracking.setMaximumSize(1000, 1000)

        self.stacked_widget = QStackedWidget()
        self.stacked_widget.addWidget(self.main_window)
        self.stacked_widget.addWidget(self.hash_cracking)
        self.stacked_widget.addWidget(self.malware_window)
        self.stacked_widget.addWidget(self.network_window)

        v_box = QVBoxLayout()
        v_box.addWidget(self.stacked_widget)
        self.setLayout(v_box)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = App()
    main_window.show()
    sys.exit(app.exec_())