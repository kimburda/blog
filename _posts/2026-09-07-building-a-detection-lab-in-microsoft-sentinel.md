---
title: Building a Detection Lab in Microsoft Sentinel
date: 2026-09-07
tags: Cyber Sentinel Microsoft SOC SC-200 Lab
---
## Background

**I have the SC-200 certification, but wanted more hands-on experience with Microsoft Sentinel specifically. So I built a small lab: simulate a real attack, detect it myself, and walk it through to a closed incident.**  

## **Set up**

1. **I created a Log Analytics workspace and enabled Microsoft Sentinel on top of it.**

![image.png](/blog/assets/uploads/image-1.png)
![image.png](/blog/assets/uploads/image-2.png)

2. **I then created and connected a Windows VM to it using the Azure Monitor Agent, collecting security logs including full command-line details. I specifically enabled command-line logging rather than relying on default process creation events, since command-line arguments are where encoded PowerShell attacks actually hide, the process name alone (`powershell.exe`) looks identical whether it's legitimate admin activity or an attacker trying to stay hidden.**

![image.png](/blog/assets/uploads/image-3.png)
![image.png](/blog/assets/uploads/image-15.png)

3. **I connected to the machine via RDP and enabled command line logging in process creation events (Event ID 4688), specifically the "Include command line in process creation events" policy, so Sentinel would capture the full command string, not just the process name.**

![image.png](/blog/assets/uploads/image-5.png)
![image.png](/blog/assets/uploads/image-6.png)

## **Simulating an Attack**

- **I installed Atomic Red Team to simulate a real attack (T1059.001, encoded PowerShell execution, a common way attackers hide commands from casual inspection by encoding them in Base64). This technique is popular because a plain-text malicious command is easy to spot in logs, but a Base64 blob just looks like noise unless you're specifically looking for it.**

![image.png](/blog/assets/uploads/image-7.png)

## **Detecting It**

1. **I then created a custom KQL query to detect the attack within Sentinel:**

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName has "powershell.exe"
| where CommandLine matches regex @"(?i)(-e |-enc |-encodedcommand)\s*[A-Za-z0-9+/=]{20,}"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
| order by TimeGenerated desc
```

**The logic here: filter to process creation events (**`EventID == 4688`**) where the new process is PowerShell, then look for command lines containing one of PowerShell's encoded-command flags (**`-e`**,** `-enc`**, or** `-encodedcommand`**) followed by a long Base64-looking string. The** `(?i)` **makes the match case-insensitive, since attackers (and legitimate scripts) don't always use consistent casing on flags. I set the minimum length at 20 characters to avoid false positives on short, legitimate encoded strings while still catching realistic payloads.**

![image.png](/blog/assets/uploads/image-8.png)

2. **I then created a scheduled analytics rule using this same query, running on a regular interval against incoming logs. As part of building the rule, I configured entity mapping, mapping the `Computer` field to the Host entity and the `Account` field to the Account entity. This matters because entity mapping is what lets Sentinel automatically correlate this alert with other activity from the same host or account later, rather than treating every alert as an isolated event with no context.**

![image.png](/blog/assets/uploads/image-14.png)

**3. After a few minutes, an alert fired, and an incident was created.**



![image.png](/blog/assets/uploads/image-10.png)

![image.png](/blog/assets/uploads/image-11.png)



## **Investigating and Closing It**

- **I investigated the alert, reviewing the full command line, parent process, and account tied to the event, and confirmed the command was part of the simulation I had run. Since the activity matched a known, intentional test rather than genuine malicious behavior, I classified it as a true positive and resolved the incident, documenting the simulation as the root cause.**

![image.png](/blog/assets/uploads/image-12.png)

## **Lessons Learned**

This detection rule works well for catching one specific pattern, PowerShell using its built-in encoded-command flags, but it has real limitations in real-world scenarios. An attacker who avoids those exact flags (for example, using `IEX (New-Object Net.WebClient).DownloadString(...)` to pull and execute a script directly, without ever touching `-enc`) would slip past this rule entirely. A more mature detection strategy would use multiple rules together, such as one for encoded commands, another for suspicious network-calling cmdlets, and another for unusual parent-child process relationships.