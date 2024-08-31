
## 编译

```
make build
```

## 运行

```
make run
```




在另一个终端中执行下面的命令：

```
echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n' | nc -l 8000 &
curl http://127.0.0.1:8000
```

在另一个终端中执行 make cat 查看输出

