# How To Receive Multicast

A simple test program, [mcrx-check](test/mcrx-check.c), is included.
It counts the received packets and prints periodic stats about the packets received.

However, in order to receive multicast traffic, something has to be sending traffic.

There are several good ways to do this, several are described below, in increasing order of setup complexity.

## Being In A Multicast-Capable Network

The simplest case is when your receiver device already lives inside a multicast-capable network, and someone on that network is already producing traffic or ingesting externally available traffic when clients join globally addressed (S,G)s.

If you're lucky enough, you might be in one of the locations that supports multicast traffic already.
Organizations connected to [internet2](https://internet2.edu/community/membership/member-list/) in many cases can consume multicast traffic from the [active senders there](https://multicastmenu.herokuapp.com/).

But most people are not so lucky, and will have to use one of the more complex options.
Setting up your own personal multicast-capable network has some challenges, but is possible without specialized equipment, as described in the [Running a multicast-capable network](#running-a-multicast-capable-network) section below.

If you are one of those lucky few, you can just run the `mcrx-check` program that this project builds for testing, and you'll be able to receieve packets that someone else is sending:

~~~
./mcrx-check -s 129.174.55.131 -g 232.44.15.9 -p 50001 -d 0 -c 2000
~~~

In most cases for the [traffic people are sending on I2](https://multicastmenu.herokuapp.com), if you can see the basic receive path working, you can also watch it as streaming video with [vlc](https://www.videolan.org/vlc/index.html) by using the source IP, group IP, and port for a vlc stream:

~~~
vlc udp://129.174.131.51@233.44.15.9:50001
~~~

## Running A Multicast-capable Network

If your ISP does not provide you a multicast network, it's still possible to set up a multicast network that can ingest traffic and then run your receivers on devices running within that network, as described in the section above.

Some detailed instructions are available in the [multicast-ingest-platform](https://github.com/GrumpyOldTroll/multicast-ingest-platform) project, and the associated [sample-network](https://github.com/GrumpyOldTroll/multicast-ingest-platform/tree/master/sample-network).

Although this option has a high one-time complexity and some maintenance burden, if you'll be working with multicast a lot it can save some hassle relative to the options below that will have you setting up config and tearing it down each time you work with it, and for each different source you want to access.

## Running Your Own Sender

[ffmpeg](https://ffmpeg.org/) and [vlc](https://www.videolan.org/vlc/index.html) both have ways to run multicast traffic.
There are several online resources with [examples](https://wiki.videolan.org/Documentation:Streaming_HowTo/Command_Line_Examples/) [showing how](https://trac.ffmpeg.org/wiki/StreamingGuide), and many reports of [mixed success](https://forum.videolan.org/viewtopic.php?t=62053) that once worked for someone, but might need troubleshooting for particular videos and installations.

These examples generate traffic for me, using a [BigBuckBunny](http://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4) download:

vlc:

~~~
vlc ~/Downloads/BigBuckBunny.mp4 --sout '#transcode {vcodec=h264,scale=Auto,acodec=mpga,ab=128,channels=2,samplerate=44100}:std{access=udp,mux=ts,dst=232.10.1.10:1234}'
~~~

ffmpeg:

~~~
ffmpeg -re -i ~/Downloads/BigBuckBunny.mp4 -c copy -f mpegts udp://232.10.1.12:1234?pkt_size=1316
~~~

When you run your own sender, it will generally output traffic on the interface with the default route, unless you've set up something more specific.

One good way to do testing with your own traffic is to run a sender on one machine and a receiver on another machine in the same LAN.
Usually this usage requires no special setup, if the LAN allows multicast traffic between its hosts.

Another good way is to run a virtual machine, and to send traffic between the host and the virtual machine.
This often requires adjusting the routing table on the sender to ensure the traffic goes to the right interface.

For example, when using a Mac, I often install [Virtualbox](https://www.virtualbox.org/wiki/Downloads) and set up a [host-only adapter](https://www.virtualbox.org/manual/ch06.html#network_hostonly) for the guest machine, and install a linux distro.
In this example, the guest IP is `192.168.56.101`, and the host IP for the host-only network is `192.168.56.1`.

Then, if you want to send traffic from the guest to the host, you can run the above ffmpeg command on the linux guest, but you'll have to set the route so the traffic goes out the host-only adapter:

~~~bash
# on the guest, before sending traffic to the host
sudo ip route add 232.0.0.0/8 via 192.168.56.1
~~~

Then you run your traffic from the linux guest:

~~~bash
# on the guest, generating traffic
ffmpeg -re -i ~/Downloads/BigBuckBunny.mp4 -c copy -f mpegts udp://232.10.1.12:1234?pkt_size=1316
~~~

Then from the host or on another guest virtual machine, you'd run a receiver and join the same traffic stream:

~~~
$ ./mcrx-check -s 192.168.56.101 -g 232.10.1.12 -p 1234 -d 0 -c 1000
02-02 01:47:52: joined to 192.168.56.101->232.10.1.12:1234 for 2s, 0 pkts received
02-02 01:47:54: joined to 192.168.56.101->232.10.1.12:1234 for 4s, 819 pkts received
passed (1000/1000 packets in 4s)
~~~

Conversely, you can do the same thing from the host to the guest, by adding a route for the destination, and using the host's IP address for the source:

~~~bash
# on an OSX host, before sending traffic to a guest
sudo route add -net 232.0.0.0/8 192.168.56.101
~~~

Then running the traffic sending to the guests:

~~~bash
# on the OSX host, sending traffic to a guest
ffmpeg -re -i ~/Downloads/BigBuckBunny.mp4 -c copy -f mpegts udp://232.10.10.2:1234?pkt_size=1316
~~~

And receiving in the guest then uses the sender's host IP and whatver group address you used:

~~~
$ ./mcrx-check -s 192.168.56.1 -g 232.10.10.2 -p 1234 -d 0 -c 1000
02-02 09:23:37: joined to 192.168.56.1->232.10.10.2:1234 for 2s, 443 pkts received
02-02 09:23:39: joined to 192.168.56.1->232.10.10.2:1234 for 4s, 840 pkts received
passed (1000/1000 packets in 4s)
~~~

## Ingesting External Traffic with AMT

There are several live sources of external traffic that can be consumed by using [AMT](https://www.rfc-editor.org/rfc/rfc7450.html) tunnels.

In order to receive multicast traffic over AMT, you'd run an AMT gateway to connect to an AMT relay that can deliver the traffic you want.

### Finding The Right Relay

Running an AMT gateway to ingest traffic requires connecting to an AMT relay that can forward the multicast traffic you're trying to receive.
There's a few different ways that can work.

#### Discovering A Relay From The Traffic's Source IP

There is some live traffic with associated [AMTRELAY](https://www.rfc-editor.org/rfc/rfc8777.html) DNS records for the source's reverse IP domain name.
Akamai runs some traffic this way and other sources might advertise relays this way as well.

AMT relays for traffic like this can be discovered with [driad.py](https://github.com/GrumpyOldTroll/libmcrx/driad.py).
For example, to discover the right relay for (23.212.185.4, 232.1.1.1), you would run:

~~~
curl -O https://raw.githubusercontent.com/GrumpyOldTroll/libmcrx/master/driad.py
RELAYIP=$(python3 driad.py 23.212.185.4)
~~~

#### Picking A Known Relay

Internet2 also has some AMT relays running that can forward the [live traffic on Internet2](https://multicastmenu.herokuapp.com).
They're hooking those relays up to the domain `amt-relay.m2icast.net.`, so you can discover them with that name:

~~~
RELAYIP=$(dig +short amt-relay.m2icast.net. | shuf | head -n 1)
~~~

#### Anycast

In theory, the method described in the original AMT spec could also be used, which is that on a global multicast backbone, a well-known reserved anycast IP address would map to the nearest AMT relay.

In practice, relays assigned to those IP addresses are not deployed at the time of this writing, and nobody has yet volunteered to deploy this kind of public infrastructure.
However, if you want to try it or deploy some locally, the [well-known anycast IPs](https://www.rfc-editor.org/rfc/rfc7450.html#section-7) are `192.52.193.1` and `2001:3::1`.

### Running An AMT Gateway

When you have a relay IP that can forward the traffic you want, you can run an AMT gateway to connect to it:

~~~
docker run -d --rm --name amtgw --privileged grumpyoldtroll/amtgw $RELAYIP
~~~

This will let you receive traffic in the `docker0` network:

~~~
./mcrx-check -s 23.212.185.4 -g 232.1.1.1 -p 5001 -i docker0 -d 0 -n 10
~~~

Instead of specifying an interface override, it's also possible to set a route for the source IP toward the interface where the AMT gateway will produce traffic:

~~~
sudo ip route add 23.212.185.4/32 dev docker0
mcrx-check -s 23.212.185.4 -g 232.1.1.1 -p 5001 -d 0 -c 10
~~~

When you're done with the traffic, it's wise to clean up by removing the route if you added one and stopping the container:

~~~
sudo ip route del 23.212.185.4/32 dev docker0
docker stop amtgw
~~~

### Forwarding Traffic From AMT Into Your LAN

If you want to use an AMT gateway to ingest the traffic and forward it on an external interface, it's possible with the `grumpyoldtroll/amtgw` image to add a macvlan interface, which will result in multicast traffic being emitted onto the 2nd connected interface.
Reading up on [docker macvlan networking](https://docs.docker.com/network/network-tutorial-macvlan/) may help determine if this makes sense in your network, and if so what config parameters to use:

~~~
docker network create --driver macvlan --subnet=192.168.56.0/24 --ip-range=192.168.56.0/26 --gateway=192.168.56.1 -o parent=enp0s8 external-multicast

docker create --rm --name amtgw --privileged grumpyoldtroll/amtgw $RELAYIP
docker network connect external-multicast amtgw
docker start amtgw
~~~

NB: note that a [docker issue](https://github.com/moby/moby/issues/25181) causes the interface ordering to be determined by their lexical name, not the order they're added.
So in this example, it's important to ensure that the macvlan's name is lexically later than `docker0` so that it's mapped inside the amtgw container, the output network is mapped to eth1 instead of eth0, since in that container eth0 is used for the AMT and DNS traffic and eth1 is used for the multicast output.

Note that for a VM, forwarding traffic into the LAN doesn't have to mean onto a wire, it can be forwarded into a host-only adapter from a guest to send traffic to the host machine or another guest machine sharing the host-only network.
This can be a useful way to work with multicast in a development environment.
