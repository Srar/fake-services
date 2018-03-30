# fake-services
fake-services 对抗端口扫描器. 

当端口扫描器发送SYN后未收到第二次握手则代表这个端口关闭反之则开启.

fake-services会自动扫描本机已监听的端口不做虚假二次握手.

未监听的端口fake-services收到SYN包后会做虚假响应回应二次握手.

此过程仍需要iptables介入拦截包防止内核回应RST.

# 依赖
* pcap
* libnet
