# F5BigIPEnum
Backend host enumeration for F5 BIG-IP load balancer.  This script is designed to enumerate all backend host data for a target IP.  Targeted and random detection methods are available to aid in this task.

## How to use
Usage options are as follows.
```
usage: F5BigIPEnum.py [-h] [-e] [-n CIDR] [-a AGENT] [-p PORT] host

Enumerate F5 BIG-IP Load Balancer

positional arguments:
  host        Target host to enumerate

optional arguments:
  -h, --help  show this help message and exit
  -e          Enumerate IPs using empty requests
  -n CIDR     Enumerate IPs using a specific CIDR range
  -a AGENT    User-Agent header (Default: BigF5Enum)
  -p PORT     Port to enumerate (Default: Gathered from initial request)
```

For initial enumeration of a host use the following command.  This command will do a single request and decode the cookie, disclosing the  backend IP and port.
```
./F5BigIPEnum.py https://127.0.0.1
Extracting F5 BIG-IP cookie info from https://127.0.0.1
Pool Name: Poolname-1
Found IP: 192.168.1.1, Port: 443
```

For further enumeration a range of backend IP's can be entered.
```
./F5BigIPEnum.py -n 192.168.1.0/24 https://127.0.0.1
Using network enumeration. Press ^C to quit

Enumerating https://127.0.0.1 for IPs from 192.168.1.0/24
Pool Name: Poolname-1
Found IP: 192.168.1.1, Port: 443
Found IP: 192.168.1.2, Port: 443
Found IP: 192.168.1.7, Port: 443
Found IP: 192.168.1.8, Port: 443
Found IP: 192.168.1.15, Port: 443
```

Using the -e command will send cookieless requests to the target in an attempt to enumerate backend targets based on load balancing.  New backend IP and port combonations will be printed to the screen.
```
./F5BigIPEnum.py -e https://127.0.0.1
Using empty request enumeration. Press ^C to quit

Enumerating Backend IPs for: https://127.0.0.1
Pool Name: Poolname-1
Found IP: 192.168.0.166, Port: 443
Found IP: 192.168.151.155, Port: 443
Found IP: 192.168.153.61, Port: 443
Found IP: 192.168.156.147, Port: 443
Found IP: 192.168.155.61, Port: 443
Found IP: 192.168.156.144, Port: 443
Found IP: 192.168.46.154, Port: 443
Found IP: 192.168.64.171, Port: 443
```

## Credits
- [vimk1ng](https://twitter.com/vimk1ng)
- [M1ndFl4y](https://twitter.com/M1ndFl4y)
