# fake-services
fake-services 对抗端口扫描器. 

当端口扫描器发送SYN后未收到第二次握手则代表这个端口关闭反之则开启.

fake-services会自动扫描本机已监听的端口不做虚假二次握手.

未监听的端口fake-services收到SYN包后会做虚假响应回应二次握手并忽略后续全部数据ACK包直到远端发送FIN做虚假挥手.

此过程仍需要iptables介入拦截包防止内核回应RST.

# 依赖
* pcap
* libnet

# 使用

```
git clone https://github.com/Srar/fake-services.git
cd fake-services
./build.sh
# ens160 应当替换成使用机器上网卡名
./fakeservice ens160
```
iptables应当设置为直接丢弃未被ACCEPT的端口包. 不做ICMP错误响应.
