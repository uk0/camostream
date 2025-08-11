
### udp_测试

* client 使用脚本 [client_udp.sh](../client_udp.sh)
* server 使用脚本 [server_udp.sh](../server_udp.sh)


```shell

echo -n "test" | nc -u 127.0.0.1 37001
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Length: 60

<html><body><h1>Hello from UDP HTML Server!</h1></body></html>
 
```