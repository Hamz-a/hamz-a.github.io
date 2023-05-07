---
layout: post
title: "Android adb reverse tethering mitm setup revised"
date: 2021-08-15 18:00:00 +0200
tags: adb android tricks reverse tethering
--- 

## Introduction
[In a previous blogpost][previous_blog_post], I've written how to combine [Gnirehtet][gnirehtet] & [proxychains][proxychains] in order to intercept traffic from mobile apps over adb while on a VPN. After some time, the setup seemed to be somewhat buggy and slow. A contact of [@FSDominguez][FSDominguez] suggested to look into port forwarding. I'd like to present a revised adb reverse tethering MITM setup.

![reversetether_mitm_vpn][reversetether_mitm_vpn]

## adb reverse
The Android Debug Bridge (ADB) command-line tool provides several utilities such as performing shell commands on the device, (un)installing apps, pushing/pulling files and port forwarding. Speaking of port forwarding, there's a nifty yet relatively less known command [`adb reverse`][adb_reverse_doc] which essentially allows us to create a reverse proxy by forwarding requests on a port on the mobile device to a port available on the host.

A quick hands-on example: 

```bash
adb reverse tcp:4444 tcp:8888
echo "hello world" > index.php
php -S 127.0.0.1:8888
```

The last command launches a PHP web server listening on port `8888` (localhost). Opening `127.0.0.1:4444` in a web browser on the mobile device gives us:

![adb_reverse_browser][adb_reverse_browser]

## Installation steps of the revised setup 

Since Android is based on Linux, it is possible to use [`iptables`][iptables] in combination with `adb reverse` in order to forward all traffic from mobile apps to the host device. Note that this requires [root access][wiki_android_root] and a [transparent intercepting proxy][wiki_transparent_proxy].

1. Install an intercepting HTTP proxy, configure it to listen on incoming connections and make sure to enable "transparent proxy"; Example: `127.0.0.1:8844`. In [Burp Suite][burp], go to Proxy > Options > Edit or add a proxy > Request handling > check "Support invisible proxying".
![burp_transparent_proxy][burp_transparent_proxy]

2. Connect your phone to your host using a USB cable.
3. Perform the following command on your host: `adb reverse tcp:8844 tcp:8844`
4. Connect your mobile device to any WiFi network.
5. Next we need to perform administrative commands on the device:
```bash
adb shell            # to perform commands on the device
su                   # switch to root
iptables -t nat -F   # flush current rules
# forward traffic from port 80 & 443 to 8844
iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 127.0.0.1:8844
iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 127.0.0.1:8844
iptables -t nat -A POSTROUTING -p tcp --dport 80 -j MASQUERADE 
iptables -t nat -A POSTROUTING -p tcp --dport 443 -j MASQUERADE
```
⚠️ if you suspect that your target app performs requests on other ports than 80 and 443, adjust above commands accordingly.

6. In order to see HTTPS traffic in your intercepting proxy, you will need to install a CA certificate on the Android device. Checkout some of NVISO's blogposts [1][nviso_1] & [2][nviso_2] and of course the manual of your favorite intercepting proxy.
7. To reset and restore your setup:
```bash
adb reverse --remove-all
adb shell
su
iptables -t nat -F
```

## Automation
I've automated above setup and commands in my [Frida Android Helper][fah_github] tool. Just run `fah rproxy` and you're good to go!

![fah_rproxy][fah_rproxy]


[previous_blog_post]: /2020/10/20/Android-adb-reverse-tethering-mitm-setup.html
[FSDominguez]: https://twitter.com/FSDominguez
[gnirehtet]: https://github.com/Genymobile/gnirehtet
[iptables]: https://linux.die.net/man/8/iptables
[burp]: https://portswigger.net/burp
[proxychains]: https://github.com/rofl0r/proxychains-ng
[wiki_android_root]: https://en.wikipedia.org/wiki/Rooting_(Android)
[wiki_transparent_proxy]: https://en.wikipedia.org/wiki/Proxy_server#Transparent_proxy
[adb_reverse_doc]: https://android.googlesource.com/platform/system/core/+/fb60e6c9aed973759e1fbd66a1dfbfc5b7cdaef6/adb/SERVICES.TXT#240
[nviso_1]: https://blog.nviso.eu/2017/12/22/intercepting-https-traffic-from-apps-on-android-7-using-magisk-burp/
[nviso_2]: https://blog.nviso.eu/2018/01/31/using-a-custom-root-ca-with-burp-for-inspecting-android-n-traffic/
[fah_github]: https://github.com/Hamz-a/frida-android-helper
[reversetether_mitm_vpn]: /assets/files/android_adb_reverse_tethering_mitm_setup_revised/reversetether_mitm_vpn.png
[adb_reverse_browser]: /assets/files/android_adb_reverse_tethering_mitm_setup_revised/adb_reverse_browser.png
[burp_transparent_proxy]: /assets/files/android_adb_reverse_tethering_mitm_setup_revised/burp_transparent_proxy.png
[fah_rproxy]: /assets/files/android_adb_reverse_tethering_mitm_setup_revised/fah_rproxy.png
