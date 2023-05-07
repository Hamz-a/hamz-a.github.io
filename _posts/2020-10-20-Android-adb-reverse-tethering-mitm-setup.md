---
layout: post
title: "Android adb reverse tethering mitm setup"
date: 2020-10-20 12:00:00 +0200
tags: adb android tricks reverse tethering
categories: blogpost
--- 

## Introduction
Traditionally, to inspect traffic for Android apps, the mobile phone and the security analyst’s PC are connected to the same Wi-Fi hotspot. The proxy settings on the mobile phone are configured to point to the analyst’s PC. Typically, an intercepting software such as [Burp Suite Pro][burp] is configured on the PC to listen on all incoming connections.

![simple_mitm][simple_mitm]

This is the simplest setup that should work in most cases. However, in some cases, the previously mentioned setup is not ideal. Consider the case where the analyst’s PC is using a corporate VPN which isolates the PC and blocks all incoming connections from the mobile phone on the same network:

![simple_mitm_vpn][simple_mitm_vpn]

In addition, sometimes it is required to perform a pentest from the corporate IP range, therefore traffic should pass through the analyst’s intercepting software and go through the corporate VPN. In such case, a new setup needs to be prepared.

In this blogpost, I am going to present a setup using Gnirehtet and proxychains.



## The setup
Recently I have bumped into [Gnirehtet][gnirehtet], a project that provides reverse tethering over adb. This allows the Android device to use the internet connection of a PC over adb. The project has two components: an Android APK (client) and a relay server. The relay server has two flavours: Java & Rust. The main difference being that Rust consumes less CPU/memory.

![reversetether_mitm_vpn][reversetether_mitm_vpn]

Next, the traffic needs be routed to Burp. I thought of using [proxychains][proxychains] for the job. It is a tool that hooks network-related functions to redirect traffic to a proxy according to a configuration file.

Trying to use proxychains with the Java version of Gnirehtet does not work. This is mainly due to the fact that the Java program runs in the Java Virtual Machine (JVM). Proxychains works by hooking libc networking-related functions in dynamically linked programs and is therefore not able to hook the Java Gnirehtet program. For this reason, this setup is going to make use of the Rust version of Gnirehtet (in addition of the performance gain).



## Installation steps
1. Install an intercepting HTTP proxy and configure it to listen on incoming connections. Example: `127.0.0.1:8888`.
2. Install proxychains. Depending on the platform you are on, this might be as simple as `brew install proxychains-ng` on MacOS. Otherwise, follow the compilation/installation instructions on [GitHub][proxychains].
3. Grab the latest [release of Gnirehtet][gnirehtetreleases]. MacOS users need to [Install Rust][installrust] in order to compile the program themselves as it is unavailable on the releases page.
```
$ git clone https://github.com/Genymobile/gnirehtet
$ cd gnirehtet/relay-rust
$ cargo build --release
```
4. Install the Gnirehtet client `adb install gnirehtet.apk` on the Android device.
5. Create a proxychains configuration file next to the Rust relay server executable with the following content:
```
$ cat proxychains.conf
[ProxyList]
http 127.0.0.1 8888
```
Note that depending on the used proxy, it is possible to use other protocols such as `socks4` instead of `http`.
6. Start the relay server using proxychains: `proxychains4 -f ./proxychains.conf ./gnirehtet relay`.
7. In another terminal, start the Android client: `./gnirehtet start`.
8. Note that in order to see HTTPS traffic in your intercepting proxy, you will need to install a CA certificate on the Android device.




[gnirehtet]: https://github.com/Genymobile/gnirehtet
[gnirehtetreleases]: https://github.com/Genymobile/gnirehtet/releases
[burp]: https://portswigger.net/burp
[proxychains]: https://github.com/rofl0r/proxychains-ng
[installrust]: https://www.rust-lang.org/tools/install
[simple_mitm]: /assets/files/android_adb_reverse_tethering_mitm_setup/simple_mitm.png
[simple_mitm_vpn]: /assets/files/android_adb_reverse_tethering_mitm_setup/simple_mitm_vpn.png
[reversetether_mitm_vpn]: /assets/files/android_adb_reverse_tethering_mitm_setup/reversetether_mitm_vpn.png
