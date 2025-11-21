---

## **Tools & Techniques Used (Compact Notes)**

### **1. Nmap**

* **Why used:** Initial service enumeration to identify open ports and detect that the web app behaves like NodeJS (based on 404 response).

### **2. Gobuster**

* **Why used:** Directory brute-forcing to discover hidden paths. This revealed **Tiny File Manager**.

### **3. Tiny File Manager (web panel)**

* **Why used:** Logged in using default credentials (`admin@123`) to access file upload functionality.

### **4. PHP Web Shell Upload**

* **Why used:** To achieve code execution via the uploads directory, enabling a **reverse shell**.

### **5. Reverse Shell (netcat / listener)**

* **Why used:** To gain interactive command execution on the target system.

### **6. hidepid=2 Observation**

* **Why used:** Explains why the user cannot see processes of other users—affects enumeration strategy.

### **7. Inspecting Nginx Config**

* **Why used:** To identify what service is running on port `9091`, leading to discovery of new vhost `soc-player.soccer.htb`.

### **8. Boolean SQL Injection (in /check)**

* **Why used:** To exploit input handling in a WebSocket endpoint for DB extraction.

### **9. BurpSuite (WebSocket interception)**

* **Why used:** To analyze and capture the WebSocket traffic needed for SQLMap input.

### **10. SQLMap (with WebSocket support)**

* **Why used:** Automate SQL injection to dump database credentials.

### **11. SSH Login using dumped creds**

* **Why used:** To obtain stable shell as the **player** user.

### **12. LinPEAS**

* **Why used:** Privilege escalation enumeration; identifies misconfigurations (e.g., doas permissions).

### **13. doas (sudo alternative)**

* **Why used:** Player user allowed running `dstat` with elevated privileges.

### **14. dstat Plugin Exploit**

* **Why used:** Craft malicious dstat plugin loaded with root privileges to escalate to root.

