# Htpp4s Authentication

## Basic Auth

### GET (without Basic Auth header)

```bash
curl -v localhost:8080/welcome
```

```
* Host localhost:8080 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:8080...
* Connected to localhost (::1) port 8080
> GET /welcome HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/8.9.1
> Accept: */*
>
< HTTP/1.1 401 Unauthorized
< Date: Wed, 16 Apr 2025 17:18:58 GMT
< Connection: keep-alive
< Content-Length: 0
<
* Connection #0 to host localhost left intact
```


### GET (with Basic Auth header)

```bash
curl -v -H "Authorization:Basic c2FuamF5OnBhc3N3b3JkMTIz" localhost:8080/welcome
```

```
* Host localhost:8080 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:8080...
* Connected to localhost (::1) port 8080
> GET /welcome HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/8.9.1
> Accept: */*
> Authorization:Basic c2FuamF5OnBhc3N3b3JkMTIz
>
* Request completely sent off
< HTTP/1.1 200 OK
< Date: Wed, 16 Apr 2025 16:56:39 GMT
< Connection: keep-alive
< Content-Type: text/plain; charset=UTF-8
< Content-Length: 23
<
Welcome, User(1,sanjay)* Connection #0 to host localhost left intact
```