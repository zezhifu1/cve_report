# Shenzhen Jixiang Tengda Technology Co., Ltd. FH451 has a Remote Code Execution vulnerability

**Vulnerability URL**: [http://0.0.0.0:80/goform/AddressNat](http://0.0.0.0:80/goform/AddressNat)

**Firmware Download Link:** [https://www.tenda.com.cn/material/show/1629](https://www.tenda.com.cn/material/show/1629)

## Vulnerability Analysis
The vulnerability occurs in the `fromAddressNat` function.

![Image 1](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromAddressNat1.png)

The program retrieves the user input parameter `page` at line 14 but does not perform any size check. When the parameter value is excessively large, it will causes a stack overflow in the `sprintf` function at line 15, which can lead to a program crash or potential exploitation.  

Cross-referenced location: from the `fromAddressNat` function, routed to `AddressNat`, at line 73.

![Image 1](https://github.com/zezhifu1/cve_report/blob/main/FH451/image/fromAddressNat2.png)
