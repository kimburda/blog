---
title: Building a Detection Lab in Microsoft Sentinel
date: 2026-09-07
tags: Cyber Sentinel Microsoft SOC SC-200 Lab
---
### Background -   

I have the SC-200 certification, but wanted more hands-on experience with Microsoft Sentinel specifically. So I built a small lab: simulate a real attack, detect it myself, and walk it through to a closed incident.  

### **Set up -** 

1. I created a Log Analytics workspace and enabled Microsoft Sentinel on top of it.

![image.png](/assets/uploads/image-1.png)

![image.png](/assets/uploads/image-2.png)

2. I then created and connected a Windows VM to it using the Azure Monitor Agent, collecting security logs including full command-line details.

![image.png](/assets/uploads/image-3.png)

![Screenshot 2026-09-07 145234.png](</assets/uploads/Screenshot 2026-09-07 145234-1.png>)

  
3. I connected to the machine via RDP and I then enabled command line logging in process creation events.  

![image.png](/assets/uploads/image-5.png)

![image.png](/assets/uploads/image-6.png)

### **Simulating an Attack**

- I installed Atomic Red Team to simulate a real attack (T1059.001 — encoded PowerShell execution, a common way attackers hide commands) and executed it on the machine.

![image.png](/assets/uploads/image-7.png)

### **Detecting It**

1. I then created my own KQL query to detect the attack within Sentinel:

![image.png](/assets/uploads/image-8.png)

2. I then created a scheduled analytics rule.
  ![Screenshot 2026-09-07 152858.png](</assets/uploads/Screenshot 2026-09-07 152858-1.png>)
3. After a few minutes, an alert fired, and an incident was created.

![image.png](/assets/uploads/image-10.png)

![image.png](/assets/uploads/image-11.png)

### **Investigating and Closing It**  

- I investigated the alert, confirmed the command was part of the simulation, classified it as a true positive, and resolved it.

![image.png](/assets/uploads/image-12.png)

