# nfqueue-mnl
A small library for packet capture and connection tracking using nfqueue, implemented with libmnl.

## Description
The purpose of *nfqueue-mnl* library is to provide an interface to Netfilter's *nfqueue* and 
*conntrack* modules. The library allows to capture packets and, optionally, obtain an associated 
connection tracking information and set connmarks. The implementation is based on the *libmnl* 
(Mini-Netlink) library, which is low-level and thus requires a lot of boilerplate code, provided 
here. The motivation for *nfqueue-mnl* was the deprecation of large parts of *libnetfilter_queue*, 
and a lack of support for connection tracking on a packet level among library projects provided by 
the Netfilter team.

The *nfqueue-mnl* library can be used as-is for writing software interfacing with Netfilter - an
example program is included. It can also serve as an example on how to use *libmnl*.

The library is not comprehensive as to the amount of information that can be obtained from
Netfilter, and actions that could be performed against it. What is currently implemented in
*nfqueue-mnl* is what I needed for my project. I am sharing this code in hope that someone finds it
useful. Additions, extensions and any other pull requests are welcome.

## Build
This section describes how to build nfqueue-mnl library and the included example program.

Prerequisites:

- autoconf/automake tools  
- gcc (reasonably modern version)  
- libmnl development files, e.g. package libmnl-dev, or download from
https://netfilter.org/projects/libmnl/index.html  

```
autoreconf --install
./configure
make
```
## Run
This section describes how to run the example program (nfqueue-test).

Prerequisites:

- root access  
- kernel 3.8 or newer  
- libmnl.so  

For this example, we capture packets arriving on port 2222, and move them to queue 0.

`iptables -I INPUT -p tcp --dport 2222 -j NFQUEUE --queue-num 0`

For IPv6 capture, replace *iptables* with *ip6tables*.

If we want to receive the conntrack information, we need to make sure the module nf_conntrack_ipv4
(and/or nf_conntrack_ipv6) is loaded. The easiest way to ensure that is to replace the above
*iptables* command with the following:

`iptables -I INPUT -p tcp --dport 2222 -m conntrack ! --ctstate INVALID -j NFQUEUE --queue-num 0`

This also works for *ip6tables*.

Having our firewall configured, we can now start *nfqueue-test* to capture packets on queue 0. Note
that this program is able to capture IPv4 and IPv6 packets; only one instance should be running if
you are interested in both.

`./nfqueue-test 0`

The argument 0 is the queue number. The program prints packet and connection information, and sends
an accept verdict back to Netfilter, while also setting a connmark. Note that this program must be
run as root or with CAP_NET_ADMIN capability.

## API
The library is provided in a header-only form.

`#include "nfqueue-mnl.h"`

### Structs
**nf_packet** collects packet and connection meta-information passed by Netfilter.

**nf_queue** holds information necessary to communicate with nfqueue (queue number and netlink
socket).

**nf_buffer** contains captured packets.

Note that *nf_buffer* is separate from *nf_queue* to allow sharing the latter between threads. See
the note about thread safety in nfqueue-mnl source code.

### Functions

`bool nfqueue_open(struct nf_queue* q, int queue_num, uint32_t queue_len)`

Open the queue of the given number and length. If queue_len argument is zero, default length value
is used.
Returns *true* on success, *false* on failure.

`void nfqueue_close(struct nf_queue* q)`

Close the queue and associated netlink socket.

`int nfqueue_receive(struct nf_queue* q, struct nf_buffer* buf, int64_t timeout_ms)`

Receive a packet (or multiple packets) from the nfqueue into buf. Because many packets may be
received in one *nfqueue_receive* call, the buffer must be iterated with *nfqueue_next* (see below).
A non-blocking socket is used, which allows setting a timeout (in millisecods). Passing zero as
*timeout_ms* causes the call to block until data is received.
Return values are: 1 (IO_READY) when data is available, 0 (IO_NOTREADY) on timeout or when data is
not ready, -1 (IO_ERROR) on failure.

`int nfqueue_next(struct nf_buffer* buf, struct nf_packet* packet)`

Iterate over packets in the buffer; please see *Example* below.
Return values are: 1 (IO_READY) on success (argument packet receives packet data), 0 (IO_NOTREADY)
on end of data, -1 (IO_ERROR) on failure.

`bool nfqueue_verdict(struct nf_queue* q, uint32_t packet_id, int verdict, int64_t connmark)`

Send verdict to nfqueue, for given packet id (which may be obtained from *nf_packet* structure). The
verdict may be NF_ACCEPT, NF_DROP, NF_QUEUE, NF_REPEAT or NF_STOP; please refer to Netfilter
documentation for meaning of these values. The argument connmark should be a 32-bit unsigned value
or -1. The latter value means that connmark is not set.
Function returns *true* on success, *false* on failure.

Note that there is currently no support for setting a packet mark, rather than a connection mark.
Such a functionality is a potentially useful addition.

### Example
This is an example pseudocode of packet capture loop, which does not include initialization or 
teardown (i.e. opening or closing of the queue).

```c
struct nf_buffer buf[1];
memset(buf, 0, sizeof(struct nf_buffer));

while (...)
{
    if (nfqueue_receive(nfqueue, buf, TIMEOUT) == IO_READY)
    {
        struct nf_packet packet[1];
        while (nfqueue_next(buf, packet) == IO_READY)
        {
            handle_packet(packet);
            free(packet->payload);
        }
    }
}
free(buf->data);
```
### Error Handling
By default the library and the example program print error messages to stderr and exit when error is
critical. This can be changed by redefining macros **LOG** and/or **DIE** before including
*nfqueue-mnl.h*. Please see source code for details.

## Authors
- **Maciej Puzio** - initial work

## License
This project as a whole is licensed under GNU General Public License, version 2 or later (at your 
choice). Parts of the source code that do not derive from the *libnetfilter_queue* project (i.e. 
the majority of code) may be relicensed under GNU Lesser General Public License, version 2.1 or 
later (at your choice). Contributions, if there are any, will be licensed under GNU Lesser General 
Public License, version 2.1 or later, unless specified otherwise.

## Acknowledgments
This project contains small sections of code from the following projects:

- *libmnl* by Pablo Neira Ayuso (LGPL 2.1 or later)  
- *libnetfilter_queue* by Pablo Neira Ayuso (GPL 2 or later)  
