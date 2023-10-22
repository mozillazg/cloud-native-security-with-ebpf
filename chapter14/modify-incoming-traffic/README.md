

```shell

curl 127.0.0.1:8080/healthz -v --user-agent 'curl/7.81.0 cmd:test________________'

tcpdump -i lo port 8080 -Xn -s 0

python3 -m http.server --bind 127.0.0.1 8080
```
