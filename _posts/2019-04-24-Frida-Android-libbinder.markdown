---
layout: post
title: "Frida Android libbinder"
date: 2019-04-24 21:45:00 +0200
tags: frida android libbinder
---

## Introduction
While doing some security research on the Android operating system, I stumbled upon the following [blackhat presentation][blackhat-ipc-presentation]. It turns out that Android has a unique inter-process communication (IPC) mechanism. Although the internal workings of this mechanism is quite complex, it is abstracted away for Android app developers. The gist of the story is that Android uses Binder for inter-process communications and that it might be a good place for malware to eavesdrop for sensitive information.

Sounds like a cool thing to hook using Frida! In this blogpost I'll describe my journey on how it's made. I will be using the Google Keep note app for demo purposes.


## Finding suitable function to hook
Most of the times there are several functions that reside on different layers that can be hooked in order to achieve a certain goal. The following resources were a great help into understanding the Android Binder architecture and the layers it contains <sup>[1][synacktiv-binder]</sup> <sup>[2][newandroidbook-binder]</sup> <sup>[3][blackhat-ipc-paper]</sup>. The following are a rough list of entries that can be hooked, sorted from high to low level:
1. Java implementation layer: a developer might implement a custom protocol to communicate between apps/services. Here we're going to hook implementation specific functions created by app developers.
2. Framework layer: this layer represents the Android standard Java classes/interfaces which developers might extend. A potential hook candidate would be `android.os.Binder`.
3. Native layer: this layer is hidden from app developers and provided transparently by Android. It is implemented as a shared library [libbinder.so][libbinder-cpp]. Particular files of interest are `Binder.cpp` and `IPCThreadState.cpp`. This layer communicates with the Kernel layer using `ioctl` syscalls in order to communicate binder messages.
4. Kernel layer: `ioctl` syscalls are handled here.

I chose to hook on the native layer. The [`ioctl`][ioctl-doc] call seemed like an interesting function to hook as it requires some manual parsing of messages in Frida. Note that it might be easier to hook higher level functions such as C++ functions or Java functions depending on your goal.


## libbinder in Android apps
Apps make use of a shared library called `libbinder.so` to interact with the Binder IPC framework. In Frida we can show the loaded modules of a particular app as follows:

```
frida -U -q -n com.google.android.keep -e "Process.enumerateModules();"

[Xiaomi Mi A2::com.google.android.keep]-> Process.enumerateModules();
[
...
    {
        "base": "0x7f91d08000",
        "name": "libbinder.so",
        "path": "/system/lib64/libbinder.so",
        "size": 561152
    },
...
]
```

Frida options explained:
- `-U` connect to USB,
	- If you have several devices connected, use `-D`; `frida-ls-devices` command to list devices
- `-q` quiet mode
- `-n` attach to app, use `-f` to spawn app
- `-e` evaluate code
	- `"Process.enumerateModules();"` JavaScript code to enumerate loaded modules.

We can grab the binary using `adb pull /system/lib64/libbinder.so` and start analysing the library but we could also grab [the source][libbinder-cpp] and start reading from there! I prefer to use a combination of both static and dynamic analysis.

Loading the binary in radare2, we can confirm that it uses `ioctl`:

```terminal
r2 -A libbinder.so           # -A run 'aaa' command to analyze all referenced code
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
...
[0x00049b10]> afl~ioctl      # list all functions and grep for ioctl
0x00047630    1 16           sym.imp.ioctl
[0x00049b10]>
```


## Hooking C function in shared library on Android with Frida

We'll be using JavaScript for our Frida hooks. First we need to find the address of `ioctl`:

```javascript
Java.perform(function(){
    var ioctl = Module.findExportByName("libbinder.so", "ioctl");
});
```

Then we can use the [`Interceptor.attach()`][frida-interceptor] with an `onEnter` callback to intercept `ioctl` function calls:

```javascript
Java.perform(function(){
    var ioctl = Module.findExportByName("libbinder.so", "ioctl");
    Interceptor.attach(ioctl, {
        onEnter: function(args) {
            // args is an array containing arguments passed to ioctl
            var fd = args[0]; // see man ioctl
            console.log("ioctl called, fd = " + fd);
        }
    })
});
```

Next we need to figure out the arguments passed to `ioctl`. Looking at the code in [IPCThreadState.cpp#905][IPCThreadState.cpp-L905] we can deduce that there are three arguments:
1. `args[0]`: An integer representing a file descriptor.
2. `args[1]`: An integer representing a certain command. We need to target a specific one `BINDER_WRITE_READ`. In [`binder.h#106`][binder.h-L106] this is defined as `#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)`. I decided to create a sample C++ file to calculate this value: `0xc0306201`.
3. `args[2]`: A pointer pointing to a `binder_write_read` struct (data). We will need to parse this struct.

The following implements above mentioned flow:

```javascript
Java.perform(function(){
    var ioctl = Module.findExportByName("libbinder.so", "ioctl");
    Interceptor.attach(ioctl, {
        onEnter: function(args) {
            var fd = args[0]; // int
            var cmd = args[1]; // int

            // value calculated from #define BINDER_WRITE_READ		_IOWR('b', 1, struct binder_write_read)
            if(cmd != 0xc0306201) return;  // if 0xc0306201 then enter BINDER_WRITE_READ flow
            var data = args[2]; // void * -> pointer to binder_write_read

            var binder_write_read = parse_struct_binder_write_read(data);
        }
    })
});
```

## Parsing `binder_write_read` struct

This particular struct is defined in [binder.h#84][binder.h-L84] as follows:
```c
struct binder_write_read {
    binder_size_t write_size;
    binder_size_t write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t read_size;
    binder_size_t read_consumed;
    binder_uintptr_t read_buffer;
};
```

We need to know the size of each element in order to parse the `binder_write_read` struct correctly. In the same header file, the following definition is declared: 
```c
#ifdef BINDER_IPC_32BIT
typedef __u32 binder_size_t;
typedef __u32 binder_uintptr_t;
#else
typedef __u64 binder_size_t;
typedef __u64 binder_uintptr_t;
#endif
```

Meaning that the size is 8 bytes for each entry on 64-bit devices. Since we'll be using modern devices, we'll stick to the x64 architecture. The following JS function parses the struct correctly using the Frida API:
```javascript
function parse_struct_binder_write_read(binder_write_read) {
    var offset = 8; // 64b

    return {
        "write_size": binder_write_read.readU64(),
        "write_consumed": binder_write_read.add(offset).readU64(),
        "write_buffer": binder_write_read.add(offset * 2).readPointer(),
        "read_size": binder_write_read.add(offset * 3).readU64(),
        "read_consumed": binder_write_read.add(offset * 4).readU64(),
        "read_buffer": binder_write_read.add(offset * 5).readPointer()
    }
}
```

The `binder_write_read` parameter is a Frida [`NativePointer`][frida-nativepointer] object, which is essentially a bridge to interact with a real pointer in memory on the device. Since structs in memory are adjacent to each other, we can use basic pointer arithmetic to read the values out of this struct.

The data structure contains a read and write section each with a pointer to a buffer, buffer size and the amount of bytes that are consumed. [`binder_thread_write()`][binder_thread_write] and [`binder_thread_read()`][binder_thread_read] are used to handle these sections.

## Lost in the data structures
Next I thought I just need to dump the buffer and I will be seeing juicy data. It turns out I was wrong and that I had to parse yet another data structure. Loading the [sourcecode][native-src] in CLion might speed up the process of getting insight on how everything is connected. A neat feature is the call hierarchy:

![clion-callgraph][clion-callgraph]

So far we've handled the logic until `binder_ioctl_write_read()`, next we need to figure out what `binder_thread_write()` does:
```c
static int binder_thread_write(struct binder_proc *proc,
			struct binder_thread *thread,
			binder_uintptr_t binder_buffer, size_t size,
			binder_size_t *consumed)
{
	uint32_t cmd;
	void __user *buffer = (void __user *)(uintptr_t)binder_buffer;
	void __user *ptr = buffer + *consumed;
	void __user *end = buffer + size;

	while (ptr < end && thread->return_error == BR_OK) {
		if (get_user(cmd, (uint32_t __user *)ptr))
			return -EFAULT;
		ptr += sizeof(uint32_t);
		trace_binder_command(cmd);
		if (_IOC_NR(cmd) < ARRAY_SIZE(binder_stats.bc)) {
			binder_stats.bc[_IOC_NR(cmd)]++;
			proc->stats.bc[_IOC_NR(cmd)]++;
			thread->stats.bc[_IOC_NR(cmd)]++;
		}
		switch (cmd) {
		case BC_INCREFS:
		case BC_ACQUIRE:
		case BC_RELEASE:
		case BC_DECREFS: {
			...
		}
		...
		case BC_TRANSACTION:
		case BC_REPLY: {
			struct binder_transaction_data tr;

			if (copy_from_user(&tr, ptr, sizeof(tr)))
				return -EFAULT;
			ptr += sizeof(tr);
			binder_transaction(proc, thread, &tr, cmd == BC_REPLY);
			break;
		}
	...
}
```

The first 4 bytes in the buffer represents a command `cmd`, different actions can be performed depending on this value. From the sources I linked previously, the values `BC_TRANSACTION` and `BC_REPLY` are of particular interest to us as they contain data transmitted through Binder. I've decided to create a JavaScript dictionary to emulate the enum:

```javascript
// http://androidxref.com/kernel_3.18/xref/drivers/staging/android/uapi/binder.h#273
var binder_driver_command_protocol = {  // enum binder_driver_command_protocol
    "BC_TRANSACTION": 0,
    "BC_REPLY": 1,
    "BC_ACQUIRE_RESULT": 2,
    "BC_FREE_BUFFER": 3,
    "BC_INCREFS": 4,
    "BC_ACQUIRE": 5,
    "BC_RELEASE": 6,
    "BC_DECREFS": 7,
    "BC_INCREFS_DONE": 8,
    "BC_ACQUIRE_DONE": 9,
    "BC_ATTEMPT_ACQUIRE": 10,
    "BC_REGISTER_LOOPER": 11,
    "BC_ENTER_LOOPER": 12,
    "BC_EXIT_LOOPER": 13,
    "BC_REQUEST_DEATH_NOTIFICATION": 14,
    "BC_CLEAR_DEATH_NOTIFICATION": 15,
    "BC_DEAD_BINDER_DONE": 16,
};
```

Technically I need to compute the values such as `_IOW('c', 1, struct binder_transaction_data)` which gives `0x40406301` but I decided to simply discard the first 3 bytes by using `& 0xff` which will then result into `0x1`. Let's add a new function which parses the command: 

```javascript
// http://androidxref.com/kernel_3.18/xref/drivers/staging/android/binder.c#1754
function handle_write(write_buffer, write_size, write_consumed) { // binder_thread_write
    var cmd = write_buffer.readU32() & 0xff; // hack
    var ptr = write_buffer.add(write_consumed + 4); // 4 = sizeof(uint32_t), the first 4 bytes contain "cmd"
    var end = write_buffer.add(write_size);

    switch (cmd) {
        // Implement cases from binder_driver_command_protocol, we're only interested in BC_TRANSACTION / BC_REPLY
        case binder_driver_command_protocol.BC_TRANSACTION:
        case binder_driver_command_protocol.BC_REPLY:
            // log('INFO', "TRANSACTION / BC_REPLY!");
            // TODO process the rest of the buffer
            break;
        default:
            // log('ERR', 'NOOP handler')
    }
}

Java.perform(function(){
    var ioctl = Module.findExportByName("libbinder.so", "ioctl");
    Interceptor.attach(ioctl, {
        onEnter: function(args) {
            var fd = args[0]; // int
            var cmd = args[1]; // int

            // value calculated from #define BINDER_WRITE_READ		_IOWR('b', 1, struct binder_write_read)
            if(cmd != 0xc0306201) return;  // if 0xc0306201 then enter BINDER_WRITE_READ flow
            var data = args[2]; // void * -> pointer to binder_write_read

            var binder_write_read = parse_struct_binder_write_read(data);

            if(binder_write_read.write_size > 0) {
                handle_write(binder_write_read.write_buffer, binder_write_read.write_size, binder_write_read.write_consumed);
            }
        }
    })
});
```

## Parsing `binder_transaction_data` struct
Whenever there's a `BC_TRANSACTION` or `BC_REPLY`, a `binder_transaction_data` struct is allocated and filled with the rest of the write buffer. Then the function `binder_transaction` is called with this struct as one of its parameters:
```c
case BC_TRANSACTION:
case BC_REPLY: {
	struct binder_transaction_data tr;

	if (copy_from_user(&tr, ptr, sizeof(tr)))
		return -EFAULT;
	ptr += sizeof(tr);
	binder_transaction(proc, thread, &tr, cmd == BC_REPLY);
	break;
}
```

[The struct][binder.h-L129] looks as follows:
```c
// http://androidxref.com/kernel_3.18/xref/drivers/staging/android/uapi/binder.h#129
struct binder_transaction_data {
	/* The first two are only used for bcTRANSACTION and brTRANSACTION,
	 * identifying the target and contents of the transaction.
	 */
	union {
		/* target descriptor of command transaction */
		__u32	handle;
		/* target descriptor of return transaction */
		binder_uintptr_t ptr;
	} target;
	binder_uintptr_t	cookie;	/* target object cookie */
	__u32		code;		/* transaction command */

	/* General information about the transaction. */
	__u32	        flags;
	pid_t		sender_pid;
	uid_t		sender_euid;
	binder_size_t	data_size;	/* number of bytes of data */
	binder_size_t	offsets_size;	/* number of bytes of offsets */

	/* If this transaction is inline, the data immediately
	 * follows here; otherwise, it ends with a pointer to
	 * the data buffer.
	 */
	union {
		struct {
			/* transaction data */
			binder_uintptr_t	buffer;
			/* offsets from buffer to flat_binder_object structs */
			binder_uintptr_t	offsets;
		} ptr;
		__u8	buf[8];
	} data;
};
```
A union can store different data types in the same memory location. This means that only one value can reside in such memory location. Memory will be allocated according to the biggest value. To emulate this in JS land, I've opted for a dictionary. The offsets are calculated manually with x64 architecture in mind:

```javascript
function parse_binder_transaction_data(binder_transaction_data) {
    return {
        "target": { // can either be u32 (handle) or 64b ptr
            "handle": binder_transaction_data.readU32(),
            "ptr": binder_transaction_data.readPointer()
        },
        "cookie": binder_transaction_data.add(8).readPointer(),
        "code": binder_transaction_data.add(16).readU32(),
        "flags": binder_transaction_data.add(20).readU32(),
        "sender_pid": binder_transaction_data.add(24).readS32(),
        "sender_euid": binder_transaction_data.add(28).readU32(),
        "data_size": binder_transaction_data.add(32).readU64(),
        "offsets_size": binder_transaction_data.add(40).readU64(),
        "data": {
            "ptr": {
                "buffer": binder_transaction_data.add(48).readPointer(),
                "offsets": binder_transaction_data.add(56).readPointer()
            },
            "buf": binder_transaction_data.add(48).readByteArray(8)
        }
    }
}
```

## Glueing it all together
Now that we've got the `binder_transaction_data` struct, we can finally dump data as we got a pointer to the data buffer and a length. The final script looks as follows:

```javascript
'use strict';

const PYMODE = false;
var CACHE_LOG = "";

function log(type, message) {
    if(message.toString() == CACHE_LOG.toString()) return; // Let's hide duplicate logs...

    CACHE_LOG = message;
    if(PYMODE) {
        send({'type':type, 'message': message});
    } else {
        console.log('[' + type + '] ' + message);
    }
}

// http://androidxref.com/kernel_3.18/xref/drivers/staging/android/uapi/binder.h#273
var binder_driver_command_protocol = {  // enum binder_driver_command_protocol
    "BC_TRANSACTION": 0,
    "BC_REPLY": 1,
    "BC_ACQUIRE_RESULT": 2,
    "BC_FREE_BUFFER": 3,
    "BC_INCREFS": 4,
    "BC_ACQUIRE": 5,
    "BC_RELEASE": 6,
    "BC_DECREFS": 7,
    "BC_INCREFS_DONE": 8,
    "BC_ACQUIRE_DONE": 9,
    "BC_ATTEMPT_ACQUIRE": 10,
    "BC_REGISTER_LOOPER": 11,
    "BC_ENTER_LOOPER": 12,
    "BC_EXIT_LOOPER": 13,
    "BC_REQUEST_DEATH_NOTIFICATION": 14,
    "BC_CLEAR_DEATH_NOTIFICATION": 15,
    "BC_DEAD_BINDER_DONE": 16,
};

// http://androidxref.com/kernel_3.18/xref/drivers/staging/android/uapi/binder.h#77
function parse_struct_binder_write_read(binder_write_read) {
    var offset = 8; // 64b

    return {
        "write_size": binder_write_read.readU64(),
        "write_consumed": binder_write_read.add(offset).readU64(),
        "write_buffer": binder_write_read.add(offset * 2).readPointer(),
        "read_size": binder_write_read.add(offset * 3).readU64(),
        "read_consumed": binder_write_read.add(offset * 4).readU64(),
        "read_buffer": binder_write_read.add(offset * 5).readPointer()
    }
}

// http://androidxref.com/kernel_3.18/xref/drivers/staging/android/uapi/binder.h#129
function parse_binder_transaction_data(binder_transaction_data) {
    return {
        "target": { // can either be u32 (handle) or 64b ptr
            "handle": binder_transaction_data.readU32(),
            "ptr": binder_transaction_data.readPointer()
        },
        "cookie": binder_transaction_data.add(8).readPointer(),
        "code": binder_transaction_data.add(16).readU32(),
        "flags": binder_transaction_data.add(20).readU32(),
        "sender_pid": binder_transaction_data.add(24).readS32(),
        "sender_euid": binder_transaction_data.add(28).readU32(),
        "data_size": binder_transaction_data.add(32).readU64(),
        "offsets_size": binder_transaction_data.add(40).readU64(),
        "data": {
            "ptr": {
                "buffer": binder_transaction_data.add(48).readPointer(),
                "offsets": binder_transaction_data.add(56).readPointer()
            },
            "buf": binder_transaction_data.add(48).readByteArray(8)
        }
    }
}

// http://androidxref.com/kernel_3.18/xref/drivers/staging/android/binder.c#1754
function handle_write(write_buffer, write_size, write_consumed) { // binder_thread_write
    var cmd = write_buffer.readU32() & 0xff;
    var ptr = write_buffer.add(write_consumed + 4); // 4 = sizeof(uint32_t), the first 4 bytes contain "cmd"
    var end = write_buffer.add(write_size);

    switch (cmd) {
        // Implement cases from binder_driver_command_protocol, we're only interested in BC_TRANSACTION / BC_REPLY
        case binder_driver_command_protocol.BC_TRANSACTION:
        case binder_driver_command_protocol.BC_REPLY:
            // log('INFO', "TRANSACTION / BC_REPLY!");
            var binder_transaction_data = parse_binder_transaction_data(ptr);

            // Show me the secrets
            log("INFO", "\n" + hexdump(binder_transaction_data.data.ptr.buffer, {
                length: binder_transaction_data.data_size,
                ansi: true,
            }) + "\n");
            break;
        default:
            // log('ERR', 'NOOP handler')
    }
}

Java.perform(function(){
    var ioctl = Module.findExportByName("libbinder.so", "ioctl");
    Interceptor.attach(ioctl, {
        onEnter: function(args) {
            var fd = args[0]; // int
            var cmd = args[1]; // int

            // value calculated from #define BINDER_WRITE_READ		_IOWR('b', 1, struct binder_write_read)
            if(cmd != 0xc0306201) return;  // if 0xc0306201 then enter BINDER_WRITE_READ flow
            var data = args[2]; // void * -> pointer to binder_write_read

            var binder_write_read = parse_struct_binder_write_read(data);

            if(binder_write_read.write_size > 0) {
                handle_write(binder_write_read.write_buffer, binder_write_read.write_size, binder_write_read.write_consumed);
            }
        }
    })
});
```

Let's run it with Frida on Google Keep notes app:

```
frida -U -l frida_android_libbinder.js -f com.google.android.keep --no-pause
```

There's a lot of traffic, so be sure to have "unlimited" buffer in your terminal. I played around with the app until the following popped up!

![result][result]

Not sure how useful this is but it was fun anyways. You can find the source code on [GitHub][github-frida-android-libbinder]!



[blackhat-ipc-presentation]: https://www.blackhat.com/docs/eu-14/materials/eu-14-Artenstein-Man-In-The-Binder-He-Who-Controls-IPC-Controls-The-Droid.pdf
[libbinder-cpp]: https://android.googlesource.com/platform/frameworks/native/+/jb-dev/libs/binder/
[synacktiv-binder]: https://www.synacktiv.com/posts/systems/binder-transactions-in-the-bowels-of-the-linux-kernel.html
[newandroidbook-binder]: http://newandroidbook.com/files/Andevcon-Binder.pdf
[blackhat-ipc-paper]: https://sc1.checkpoint.com/downloads/Man-In-The-Binder-He-Who-Controls-IPC-Controls-The-Droid-wp.pdf
[ioctl-doc]: http://man7.org/linux/man-pages/man2/ioctl.2.html
[frida-interceptor]: https://www.frida.re/docs/javascript-api/#interceptor
[IPCThreadState.cpp-L905]: http://androidxref.com/9.0.0_r3/xref/frameworks/native/libs/binder/IPCThreadState.cpp#905
[binder.h-L84]: http://androidxref.com/9.0.0_r3/xref/bionic/libc/kernel/uapi/linux/android/binder.h#84
[binder.h-L106]: http://androidxref.com/9.0.0_r3/xref/bionic/libc/kernel/uapi/linux/android/binder.h#106
[frida-nativepointer]: https://www.frida.re/docs/javascript-api/#nativepointer
[binder_thread_write]: http://androidxref.com/kernel_3.18/xref/drivers/staging/android/binder.c#1754
[binder_thread_read]: http://androidxref.com/kernel_3.18/xref/drivers/staging/android/binder.c#2141
[native-src]: https://android.googlesource.com/platform/frameworks/native/+/refs/heads/master
[clion-callgraph]: /assets/files/frida_android_libbinder_2019_04/clion_call_graph.png
[binder.h-L129]: http://androidxref.com/kernel_3.18/xref/drivers/staging/android/uapi/binder.h#129
[result]: /assets/files/frida_android_libbinder_2019_04/result.png
[github-frida-android-libbinder]: https://github.com/Hamz-a/frida-android-libbinder









