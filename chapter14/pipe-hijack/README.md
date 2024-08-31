
## 编译

```
make build
```

## 运行

```
make run
```


在另一个终端中执行以下命令

```
echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\necho hello' | nc -l 8080  &
curl http://127.0.0.1:8080 | bash -
```
