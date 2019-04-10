---
layout: post
title: "Frida Android Helper"
date: 2019-04-10 21:45:00 +0200
tags: frida android adb python
---

One of my favorite tools for Android app security assessments is [frida][frida]. Frida is a cross platform dynamic instrumentation tool that can help with dynamic analysis of apps and bypass security mechanisms implemented in these apps.
The community behind Frida is also extremely active and supportive. Sometimes a few releases are pushed per week with a ton of improvements and bug fixes!

There are two "main" ways to use Frida on Android:
-	Repackage the target APK with a Frida Gadget;
-	Use a rooted Android device and install Frida server.

Since I need a rooted Android device to perform my security tests anyways and the repackaging process is time consuming, I usually opt for the second option. With the fast paced development of Frida, I sometimes encounter the following error:

```
➜ frida-ps -Uai
Failed to enumerate applications: unable to communicate with remote frida-server;
please ensure that major versions match and that the remote Frida has the feature you are trying to use
```

Installing the latest Frida is easy as described in the documentation:
1. Grab the [latest release from GitHub][frida-latest-release].
2. Extract the release.
3. Push the release to the device.
3. `chmod 755` it.
4. Run as root in background.

After a few times of doing this I thought: why not automate this process? Enter Frida Android Helper.
The command line tool is written in Python and makes use of [`pure-python-adb`][pure-python-adb] to interface with the ADB server.

For starters I've added a server module to start, stop, reboot and most importantly update the Frida server to the latest release.
The GitHub API is used to fetch the latest Android Frida server based on the architecture of the device (arm/x86 32/64).

There is one hack though:
```python
def perform_cmd(device: Device, command: str, root: bool = False, timeout: int = None):
    if root:
        command = "su -c {}".format(command)
    try:
        return device.shell(command, timeout=timeout)
    except:
        pass

def launch_frida_server(device: Device):
    # hack: launch server, "forever sleep" and put in background. Short timeout to break off connection
    perform_cmd(device, "/data/local/tmp/frida-server && sleep 2147483647 &", root=True, timeout=1)
```

The frida-server needs to be launched as root and put in the background. I've hacked around with fork `&`, double fork `(./frida-server &) &`, nohup, `su -c` etc...
Either the frida server exits directly, or the command line "hangs" since TTY (socket?) is still open. Therefore the hack consists of running frida-server as root, sleeping infinitely, putting this into the background and then abruptly closing the connection from client side using `timeout=1`. The python ADB library throws a timeout exception which is caught in `perform_cmd()`. Ideas for a cleaner solution are welcome!

Hopefully I'll add more modules to make the Frida experience on Android smoother. Ideas and bug reports are therefore welcome!



[frida]: https://www.frida.re/
[frida-latest-release]: https://github.com/frida/frida/releases/latest
[pure-python-adb]: https://github.com/Swind/pure-python-adb/