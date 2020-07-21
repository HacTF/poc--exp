# This is an educational exercise. Use at your own risk.

# CVE-2020-1350 Exploit aka SIGRED
## [This is a lesson as to why you should not trust binaries on the internet.](https://blog.zsec.uk/cve-2020-1350-research/), the [workaround fix is genuine](https://github.com/ZephrFish/CVE-2020-1350/blob/master/Fix.bat).
### Workaround Fix
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v "TcpReceivePacketSize" /t REG_DWORD /d 0xFF00 /f
net stop DNS && net start DNS
```
- MS Link: https://support.microsoft.com/en-gb/help/4569509/windows-dns-server-remote-code-execution-vulnerability
Microsoft has released the security patch, you can download the patch here: https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1350

### Windows Binary PoC
```
./CVE-2020-1350.exe will run the exploit.
```

View README.pdf for more information on how to use the binary.

Source code is available here: https://github.com/zoomerxsec/Fake_CVE-2020-1350


### Running the exploit on Linux

Change the target IP in exploit.sh then do:

```
chmod +x exploit.sh
./exploit.sh
```

## Repo Info
- CVE-2020-1350.exe (sha256sum 9e6da40db7c7f9d5ba679e7439f03ef6aacee9c34f9a3f686d02af34543f2e75) - Benign binary which opens rick roll and pings canary token
- Fix.bat - Batch file that applies the fix from Microsoft
- LICENCE - The licence file, also does nothing
- PoC.exe (sha256sum bf9657ff82065a676bc2aeb07877d5964a193da244e943ee37f08b931c9868b7)-  Benign binary which opens cmd.exe and additionally pings canary token
- README.md - Details the README of the repo
- windows-exploit.ps1 - Rick roll in shell, also benign


### Additional Resources

- https://blog.zsec.uk/cve-2020-1350-honeypoc/ - Statistics from this project
- https://blog.zsec.uk/cve-2020-1350-research/ - Explanation on this project :-)
- https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_exploit_cve_2020_1350.yml - Signa rules for detection
- https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/ - Vulnerability Writeup
- https://blog.menasec.net/2019/02/threat-hunting-24-microsoft-windows-dns.html - Threathunting the vuln
- https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1350 - CVE-2020-1350 | Windows DNS Server Remote Code Execution Vulnerability
- https://msrc-blog.microsoft.com/2020/07/14/july-2020-security-update-cve-2020-1350-vulnerability-in-windows-domain-name-system-dns-server/ - July 2020 Security Update: CVE-2020-1350 Vulnerability in Windows Domain Name System (DNS) Server
- https://github.com/tinkersec/cve-2020-1350 Tinkersec PoC, also not real


### Contributors
- https://twitter.com/ZephrFish 
- https://twitter.com/TJ_Null 
- https://twitter.com/ZoomerX 
- https://twitter.com/TheCyberViking 
- https://twitter.com/Techypossible
- https://twitter.com/BushidoToken

