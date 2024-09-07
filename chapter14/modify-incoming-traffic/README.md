
## 编译

```
make build
```

## 运行

```
make run
```


在另一个终端中执行:

```
echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n' | nc -l 8080 &
echo -e 'GET /route-1 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: curl/7.81.0 cmd:test-foo-bar-foobar\r\n' | nc 127.0.0.1 8080
```

