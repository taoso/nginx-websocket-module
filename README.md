# WebSocket Module for Nginx

## how to work

Nginx use the multiprocess model. The worker process has no idea of eatch other.
When there is a incoming http request, the request has been processed by one
worker. This model is simple yet efficient. It works well for nginx as a proxy
server.

However, if you want nginx work as an websocket server, we would face
an intractable problem. Suppose we have two workers, A and B. When an websocket
client comes, it will be processed by A or B. Let's suppose it by A. And nginx
then send some id info the the client. If we want send somethig to the client,
we need make a request, as well. However, our push request maybe processed by
another worker B. The worker B has no idea about the client. It failed.

In order to fixup this problem, we make every worker listen an unique port
before the worker start. However, in the latest nginx code base, it is hard to
add listen port on fly. So we make some nginx inner api public to simplify this
process. We will try to make this patch be merged into the nginx code base.

## install

1. install [libwslay](https://github.com/tatsuhiro-t/wslay)
1. download nginx source code
1. go to base dir of nginx source code and run `patch -p1 < /path/to/ngx_listen.diff`
1. then run `./auto/configure --prefix=/tmp/ngx --add-module=path/to/src/nginx-websocket-module --with-debug`

## usage

This module only offer one directive, **websocket**. This directive can be only
used in the `location` context. An example conf:

```
location /ws {
    websocket pingintvl=10000 idleintvl=15000;
}
````

The config above will make nginx listen websocket request on the `/ws` path.
The `pingintvl` arg is used to set the interval to send ping message to the
client. And the `idleintvl` arg is used to detect client timeout. If there is 
no message send or receive after `pingintvl`, nginx will send a `PING`,
message and the client will ack the `PONG` message, which will reset the ping
timer. If ther is no message send or receive after `idleintvl`, nginx will
just close the connection. Both units are millisecond. If not set, the default
value of pingintvl is 5 minute and idleintvl 6 minute.

But why let server send the `PING` message? It is because that the browser does
not offer the api to ping server for javascript.

Then you can make a websocket handshake to nginx. Once the handshake finished,
nginx will send an text message reads
`http://12@172.16.71.231:48775/ws,http://12@172.16.71.211:48775/ws`.
You can post message to this url by httpie like:
```
echo 123|http http://12@172.16.71.231:48775/ws
```

## todo
- [ ] ipv6
- [x] more debug log
- [ ] push binary data
- [ ] process upstream message
