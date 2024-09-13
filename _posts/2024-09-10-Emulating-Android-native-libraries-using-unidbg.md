---
layout: post
title: "Emulating Android native libraries using unidbg"
date: 2024-09-10 04:00:00 +0200
tags: android reverse engineering unidbg
categories: blogpost
image: /assets/files/emulating_android_native_libraries_using_unidbg/og_social.jpg
--- 

## Introduction
[Unidbg][unidbg_github] is an open-source framework to emulate Android native libraries (and to a certain extent has experimental iOS emulation capabilities). There are a few use cases where emulating Android libraries is beneficial. I will cover a single use case to demonstrate how to use unidbg as I believe the security and reverse engineering scene lacks English written tutorials regarding this powerful tool. This blogpost will contain a step-by-step guide on how to use unidbg along with some errors you might encounter and how to fix them. 

If you have never heard of unidbg or [unicorn][unicorn], I would suggest reading this [introductory blogpost][intro_unidbg] as it contains some background information when it comes to binary analysis, reverse engineering, tooling and where unidbg fits.

Unidbg is interesting because unlike other tools, it understands and is able to emulate JNI calls such as `JNI_Onload` and `Java_*`. This means that calls to the JVM can be mocked. In addition, it supports ARM32, ARM64, filesystem, hooking ([dobby][dobby], [xHook][xHook]), debugging and more!

## Some context
In general, a mobile app communicates with a single or several backends. Developers might make it harder for third party developers, reverse engineers or hackers to integrate with their backend using various tricks including binary obfuscation, root/hook/tamper detection, TLS pinning, request & response encryption and more. Another way is by implementing a signature mechanism where each request is signed. This could look as simple as:
> hmac(request payload, secret)

The backend subsequently grabs the request payload and verifies it with the shared secret. This relatively simple routine is often easily defeated by a seasoned reverse engineer. Some developers take it a step further by creating a more complex signing method and incorporate various other variables such as device ID, OS version, URL, and time. The time parameter is interesting as it prevents to a certain extent to replay requests if the adversary does not know the signing procedure and the secret. 

Native Android apps are commonly written in Java/Kotlin. However, since the source code of these are often easily recoverable, developers might opt for a more obscure approach by implementing the signing mechanism in C/C++ using the [Android NDK][android_ndk]. This is done through the [Java Native Interface (JNI)][android_jni].

![jni_overview][jni_overview]

## Use case
Let's say we are pentesting an Android app and its respective backend in a black-box manner. If the requests are signed, pentesting the backend is not straightforward since we first have to figure out how to sign our modified requests. In general, there are a few approaches:
1. **Entirely reverse engineer the signing function:** I would recommend trying this method first time-boxed. Most apps do not implement any signing method and if they do, it is quite basic. The signing method can then be re-implemented as a standalone script or as a Burp plugin. 
2. **Hook relevant signing function:** sometimes reverse engineering and re-implementing the entire signing function can be complex and time consuming. Another approach is to use [Frida][frida] or a similar hooking framework to sign custom payloads. This requires identifying the function responsible for signing payloads and figuring out a way to call it using a hooking framework with the right parameters. [Brida][brida] is a nice Burp plugin that helps in these types of endeavors. The "downside" of this approach, is that you'd still need an active device in order to sign requests.
3. **Emulate the signing function:** this brings us to emulation, or more precisely, partial emulation. Sometimes we do not necessarily want to emulate the full app as it could be resource intensive, and/or requires bypassing other checks including emulation detection. This approach allows us to reduce our reverse engineering efforts and directly emulate the relevant signing function. Once implemented, it eleminates the need for an active device.<br>Note that a major drawback of this approach is that it can get tricky to setup correctly. It is therefore important to investigate the level of obfuscation and determine the ultimate goal while keeping in mind how much time is allocated for such task.

In this blogpost, I'm going to show how to leverage unidbg and emulate an Android native library. I have created a [PoC Android app][HelloSignJNI] based on [hello-jni][hellojni] and [hmac_sha256][hmac_sha256] that implements a [YOLO signing][yolo_signing] mechanism which is going to be used as an example. Grab [the APK from here][hellosignjni_release] to follow along.

![app_poc][app_poc]

## Some reverse engineering
First, we have to determine where the signing procedure is occuring using a reverse engineering tool like [Ghidra][ghidra] or [JEB Decompiler][jeb]. This might take some time to figure out with bigger and more complex apps. However, since our PoC app is small and does not have any obfuscation, it is quite straightforward. The **`native`** method modifier and an invocation call using **`System.loadLibrary`** in Java are quick giveaways that something is implemented using the JNI API. In the following recovered code, the library **`hellosignjni`** is loaded and a call to the native **`sign`** function is exposed which accepts a String as parameter:

![recovered_code1][recovered_code1]

Checking the contents of the APK file, we indeed will find a `libhellosignjni.so` file. In addition, the sign function implemented in C++ can be found and (partially) decompiled as well:

![recovered_code2][recovered_code2]

Note that the function name follows the convention of `Java_ + package name + class name + method name`. This is not always the case. For more information, see ["JNI register natives"][jni_register_natives].

After a quick analysis, we can conclude that the app accepts an input string from the user, calls the native sign function with the user string as parameter. The native sign function returns a signature. This is a relatively simple routine and we could attempt to reverse engineer the signing function and re-implement it. However, for demonstration purposes, we are going to take the unidbg route.

## Forking unidbg
Navigating and reviewing the test cases is arguably one of the best ways to figure out how to use unidbg:
![unidbg_test_cases][unidbg_test_cases]

I tend to git clone the source code from GitHub and work directly on top of the source code. Mostly because the maven repository is not updated regularly:
![maven_repo][maven_repo]

Let's first clone the unidbg repository and open it using [Intellij IDEA][idea]:
```
➜  IdeaProjects git clone https://github.com/zhkl0228/unidbg --depth 1
Cloning into 'unidbg'...
remote: Enumerating objects: 1915, done.
remote: Counting objects: 100% (1915/1915), done.
remote: Compressing objects: 100% (1351/1351), done.
remote: Total 1915 (delta 454), reused 1264 (delta 216), pack-reused 0 (from 0)
Receiving objects: 100% (1915/1915), 143.32 MiB | 506.00 KiB/s, done.
Resolving deltas: 100% (454/454), done.
Updating files: 100% (1473/1473), done.
```

Unidbg is written in a modular way, which is also why it might be better to create our own module. On the left side, it can be seen which modules are available within unidbg:
![unidbg_create_new_module][unidbg_create_new_module]

We'll name our module `pocsigner`, use Maven, add some sample code, and set a custom GroupId:
![unidbg_create_new_module_settings][unidbg_create_new_module_settings]

The module depends on the `unidbg-android` module. We'd need to add it as a dependency in the `pom.xml` file of our `pocsigner`  module:
```xml
    <dependencies>
        <dependency>
            <groupId>com.github.zhkl0228</groupId>
            <artifactId>unidbg-android</artifactId>
            <version>0.9.9-SNAPSHOT</version>
            <scope>compile</scope>
        </dependency>
    </dependencies>
```

## Creating and configuring the emulator
Time to add a new class in our module which will contain all the signing emulation logic:

![unidbg_create_signer_class][unidbg_create_signer_class]

This class should extend the `AbstractJni` class. We'll add a constructor to load the path of the `.so` file we will emulate:
```java
package me.bhamza.example;

import com.github.unidbg.linux.android.dvm.AbstractJni;

public class Signer extends AbstractJni {
    private final String soFilePath;
    public Signer(String soFilePath) {
        this.soFilePath = soFilePath;
    }
}
```

I prefer to setup the emulation logic in the constructor. Unidbg provides a builder class `AndroidEmulatorBuilder`. Since the `.so` file is a 64-bit binary, we'll create an emulator for 64-bit and set the process name the same as the package name. In addition, we'll create a DalvikVM and set its verbosity to false. You might want to set this to true for debugging purposes. We'll also load the shared library `.so` with the instantiated DalvikVM using the `loadLibrary()` call:

```java
package me.bhamza.example;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;

import java.io.File;

public class Signer extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM dalvikVM;
    private final DalvikModule dalvikModule;
    private final String soFilePath;

    public Signer(String soFilePath) {
        this.soFilePath = soFilePath;

        this.emulator = AndroidEmulatorBuilder.for64Bit().setProcessName("me.bhamza.hellojni").build();
        this.dalvikVM = emulator.createDalvikVM();
        this.dalvikVM.setVerbose(false);
        this.dalvikModule = dalvikVM.loadLibrary(new File(soFilePath), false);
    }
}
```

Ideally we would add some logic to check if the `.so` file exists and do some error handling, but we'll leave that for now. Let's quickly jump to the main class and instantiate our Signer class in order to start testing if our initial code works:
```java
package me.bhamza.example;

public class Main {
    public static void main(String[] args) {
        Signer signer = new Signer("/tmp/libhellosignjni.so");
    }
}
```

## Fixing LibraryResolver error

After running the code, we are greeted with some errors:
```
INFO: libhellosignjni.so load dependency libc.so failed
Sept 10, 2024 2:09:58 AM com.github.unidbg.linux.AndroidElfLoader resolveSymbols
INFO: [libhellosignjni.so]symbol ElfSymbol[name=free, type=function, size=0] is missing relocationAddr=RW@0x120d06f0[libhellosignjni.so]0xd06f0, offset=0x0
```
![unidbg_initial_error][unidbg_initial_error]

It seems like the emulator is not able to find a few dependencies (shared libraries), and therefore is not able to find certain symbols. Cross-checking with [the sample test code][library_resolved_test_code] shipped with unidbg, we notice how it is setting a library resolver. After adding this line in the constructor the error is resolved:
```java
this.emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
```

## DvmClass and target method signature
Next we need to create a `DvmClass` in order to be able to interact with our target class. In addition, we need to define the signature of the sign method within the target class:
```java
public class Signer extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM dalvikVM;
    private final DalvikModule dalvikModule;
    private final DvmClass dvmMainActivity;
    private final String sign_method_signature;
    private final String soFilePath;

    public Signer(String soFilePath) {
        this.soFilePath = soFilePath;

        this.emulator = AndroidEmulatorBuilder.for64Bit().setProcessName("me.bhamza.hellojni").build();
        this.emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        this.dalvikVM = emulator.createDalvikVM();
        this.dalvikVM.setVerbose(false);
        this.dalvikModule = dalvikVM.loadLibrary(new File(soFilePath), false);

        this.dvmMainActivity = dalvikVM.resolveClass("me/bhamza/hellosignjni/MainActivity");
        this.sign_method_signature = "sign(Ljava/lang/String;)Ljava/lang/String;";
    }
}
```
The signature could be manually constructed following [this guide][java_method_signature_guide]. Otherwise, use [`dex2jar`][dex2jar] and extract `.class` files. Search for the target class and run:
```
javap -s MainActivity.class
```
![dex2jar_class_method_signature][dex2jar_class_method_signature]

Another method is by using [`apktool d app-debug.apk`][apktool] which will generate smali code. We can then search for `class path->method` to find the complete method signature as follows:
![apktool_class_method_signature][apktool_class_method_signature]

## Calling the sign method
Let's add a `sign` function to our `Signer` class. It accepts a single `String` parameter (the input that needs to be signed) and returns a `String` (the signature):
```java
public String sign(String message) {
}
```
We cannot feed parameters directly to the emulator. For that, we need to use a proxy which basically creates objects (`DvmObject`) for us within the DalvikVM. If you check the source code of [`ProxyDvmObject.createObject`][ProxyDvmObject], you'll notice various switch cases to handle different types including a Java String:
```java
public String sign(String message) {
    DvmObject<?> dvm_message = ProxyDvmObject.createObject(this.dalvikVM, message);
}
```
Next we want to call the `sign` function. We can do this with the `DvmClass dvmMainActivity`. If you check the available methods using Intellij's auto-complete, you'll notice different methods. The main difference is whether the method is static or not, and what type of return value it has:
![unidbg_call_class_method_ways][unidbg_call_class_method_ways]

Since our method is static and returns a String (which is an Object), we'd opt for `callStaticJniMethodObject`. Notice how the call also returns a `DvmObject`. We can get the result of that object using the `getValue()` method:
```java
public String sign(String message) {
    DvmObject<?> dvm_message = ProxyDvmObject.createObject(this.dalvikVM, message);
    DvmObject<String> ret_val = dvmMainActivity.callStaticJniMethodObject(emulator, sign_method_signature, message);
    return ret_val.getValue();
}
```

Let's update the main function to call the `Signer.sign()` function with some value:
```java
public class Main {
    public static void main(String[] args) {
        Signer signer = new Signer("/tmp/libhellosignjni.so");
        System.out.println(signer.sign("helloworld"));
    }
}
```

## Fixing `java.lang.IllegalStateException: Please vm.setJni(jni)` error
After running the code again, we get the following error:
```
java.lang.IllegalStateException: Please vm.setJni(jni)
    at com.github.unidbg.linux.android.dvm.Hashable.checkJni(Hashable.java:8)
    at com.github.unidbg.linux.android.dvm.DvmClass.getStaticMethodID(DvmClass.java:101)
    at com.github.unidbg.linux.android.dvm.DalvikVM64$110.handle(DalvikVM64.java:1787)
    at com.github.unidbg.linux.ARM64SyscallHandler.hook(ARM64SyscallHandler.java:121)
    at com.github.unidbg.arm.backend.UnicornBackend$11.hook(UnicornBackend.java:345)
    at unicorn.Unicorn$NewHook.onInterrupt(Unicorn.java:128)
    at unicorn.Unicorn.emu_start(Native Method)
```

Unidbg luckily can sometimes be quite explicit on what needs to be fixed. Apparently we need to call the `setJni` function as follows in our constructor:
```java
    public Signer(String soFilePath) {
        this.soFilePath = soFilePath;

        this.emulator = AndroidEmulatorBuilder.for64Bit().setProcessName("me.bhamza.hellojni").build();
        this.emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        this.dalvikVM = emulator.createDalvikVM();
        this.dalvikVM.setJni(this); // <----- ADDED
        this.dalvikVM.setVerbose(false);
        this.dalvikModule = dalvikVM.loadLibrary(new File(soFilePath), false);

        this.dvmMainActivity = dalvikVM.resolveClass("me/bhamza/hellosignjni/MainActivity");
        this.sign_method_signature = "sign(Ljava/lang/String;)Ljava/lang/String;";
    }
```

## Fixing `java.lang.UnsupportedOperationException` error
When running the code again, we get another error:
```
java.lang.UnsupportedOperationException: java/time/LocalDate->now()Ljava/time/LocalDate;
    at com.github.unidbg.linux.android.dvm.AbstractJni.callStaticObjectMethodV(AbstractJni.java:504)
    at com.github.unidbg.linux.android.dvm.AbstractJni.callStaticObjectMethodV(AbstractJni.java:438)
    at com.github.unidbg.linux.android.dvm.DvmMethod.callStaticObjectMethodV(DvmMethod.java:59)
    at com.github.unidbg.linux.android.dvm.DalvikVM64$112.handle(DalvikVM64.java:1836)
    at com.github.unidbg.linux.ARM64SyscallHandler.hook(ARM64SyscallHandler.java:121)
    at com.github.unidbg.arm.backend.UnicornBackend$11.hook(UnicornBackend.java:345)
    at unicorn.Unicorn$NewHook.onInterrupt(Unicorn.java:128)
    at unicorn.Unicorn.emu_start(Native Method)
    at com.github.unidbg.arm.backend.UnicornBackend.emu_start(UnicornBackend.java:376)
    at com.github.unidbg.AbstractEmulator.emulate(AbstractEmulator.java:378)
    at com.github.unidbg.thread.Function64.run(Function64.java:39)
    at com.github.unidbg.thread.MainTask.dispatch(MainTask.java:19)
    at com.github.unidbg.thread.UniThreadDispatcher.run(UniThreadDispatcher.java:175)
    at com.github.unidbg.thread.UniThreadDispatcher.runMainForResult(UniThreadDispatcher.java:99)
    at com.github.unidbg.AbstractEmulator.runMainForResult(AbstractEmulator.java:341)
    at com.github.unidbg.arm.AbstractARM64Emulator.eFunc(AbstractARM64Emulator.java:262)
    at com.github.unidbg.Module.emulateFunction(Module.java:163)
    at com.github.unidbg.linux.android.dvm.DvmObject.callJniMethod(DvmObject.java:135)
    at com.github.unidbg.linux.android.dvm.DvmClass.callStaticJniMethodObject(DvmClass.java:316)
    at me.bhamza.example.Signer.sign(Signer.java:35)
    at me.bhamza.example.Main.main(Main.java:6)
```
Let's check what's at [`com.github.unidbg.linux.android.dvm.AbstractJni.callStaticObjectMethodV(AbstractJni.java:504)`][AbstractJni504]:
![unidbg_UnsupportedOperationException_1][unidbg_UnsupportedOperationException_1]

Basically what is happening is that the compiled C/C++ code is emulated and is making calls to the Java layer through JNI. Unidbg implemented some of these calls and uses signatures to detect them. Once detected, it handles it case by case and returns the appropriate object accordingly. If it does not find the signature, it throws an `UnsupportedOperationException` exception since it does not know how to handle that specific call.

In our case, as can be seen in the following decompiled code, the shared library performs a call to the [Java LocalDate.now() method][localdate_now]:

![jeb_decompiler_localdate_now_call][jeb_decompiler_localdate_now_call]

Since we have previously defined our `Signer` class as an extension of the `AbstractJni` class, we can override the `callStaticObjectMethodV` method and implement the missing call ourselves. This looks as follow:
```java
@Override
public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
    switch (dvmMethod.getSignature()) {
        case "java/time/LocalDate->now()Ljava/time/LocalDate;":
            return ProxyDvmObject.createObject(dalvikVM, LocalDate.now());
    }
    return super.callStaticObjectMethodV(vm, dvmClass, dvmMethod, vaList);
}
```

We add our own signature, make a call to `LocalDate.now()`, wrap it with `ProxyDvmObject.createObject` and return it, apply the built-in signatures by unidbg by calling the parent method as a default fallback.

If we run the code, we get a similar error again but this time for the `LocalDate->toString()` method:
```
java.lang.UnsupportedOperationException: java/time/LocalDate->toString()Ljava/lang/String;
    at com.github.unidbg.linux.android.dvm.AbstractJni.callObjectMethodV(AbstractJni.java:417)
    at com.github.unidbg.linux.android.dvm.AbstractJni.callObjectMethodV(AbstractJni.java:262)
    at com.github.unidbg.linux.android.dvm.DvmMethod.callObjectMethodV(DvmMethod.java:89)
    at com.github.unidbg.linux.android.dvm.DalvikVM64$32.handle(DalvikVM64.java:559)
    at com.github.unidbg.linux.ARM64SyscallHandler.hook(ARM64SyscallHandler.java:121)
    at com.github.unidbg.arm.backend.UnicornBackend$11.hook(UnicornBackend.java:345)
    at unicorn.Unicorn$NewHook.onInterrupt(Unicorn.java:128)
    at unicorn.Unicorn.emu_start(Native Method)
    at com.github.unidbg.arm.backend.UnicornBackend.emu_start(UnicornBackend.java:376)
    at com.github.unidbg.AbstractEmulator.emulate(AbstractEmulator.java:378)
    at com.github.unidbg.thread.Function64.run(Function64.java:39)
    at com.github.unidbg.thread.MainTask.dispatch(MainTask.java:19)
    at com.github.unidbg.thread.UniThreadDispatcher.run(UniThreadDispatcher.java:175)
    at com.github.unidbg.thread.UniThreadDispatcher.runMainForResult(UniThreadDispatcher.java:99)
    at com.github.unidbg.AbstractEmulator.runMainForResult(AbstractEmulator.java:341)
    at com.github.unidbg.arm.AbstractARM64Emulator.eFunc(AbstractARM64Emulator.java:262)
    at com.github.unidbg.Module.emulateFunction(Module.java:163)
    at com.github.unidbg.linux.android.dvm.DvmObject.callJniMethod(DvmObject.java:135)
    at com.github.unidbg.linux.android.dvm.DvmClass.callStaticJniMethodObject(DvmClass.java:316)
    at me.bhamza.example.Signer.sign(Signer.java:45)
    at me.bhamza.example.Main.main(Main.java:6)
```
As you might have guessed, the signing function incorporates a date in its algorithm. This time, we need to override the `callObjectMethodV` method:
```java
@Override
public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
    switch (signature) {
        case "java/time/LocalDate->toString()Ljava/lang/String;":
            // System.out.println(dvmObject.getValue().toString()); // print the date
            return new StringObject(dalvikVM, dvmObject.getValue().toString());
    }
    return super.callObjectMethodV(vm, dvmObject, signature, vaList);
}
```

After running the code for a final spin, the following is printed on screen:
```
0e1ec4b1498b140528385a8e872bcdfce985c9f51933e8f8542c7e253042cfe7
```
It is always a good idea to cross-check values with the real app and see if the generated value corresponds to the one from the app. It seems like we have successfully emulated the shared Android library!
![app_double_check][app_double_check]

Check out the final [source code here][show_me_the_code].<br>
Do you have questions? Want to see more? DM me.


[unidbg_github]: https://github.com/zhkl0228/unidbg
[unicorn]: https://www.unicorn-engine.org/
[intro_unidbg]: https://medium.com/@parker_appsec/basic-introduction-to-unidbg-25593f3d0b57
[android_ndk]: https://developer.android.com/ndk/guides
[android_jni]: https://developer.android.com/training/articles/perf-jni
[jni_overview]: /assets/files/emulating_android_native_libraries_using_unidbg/jni_overview.svg
[frida]: https://frida.re/
[brida]: https://github.com/federicodotta/Brida
[yolo_signing]: https://blog.trailofbits.com/2024/08/21/yolo-is-not-a-valid-hash-construction/
[HelloSignJNI]: https://github.com/Hamz-a/HelloSignJNI
[hellojni]: https://developer.android.com/ndk/samples/sample_hellojni
[hmac_sha256]: https://github.com/h5p9sl/hmac_sha256
[app_poc]: /assets/files/emulating_android_native_libraries_using_unidbg/app_poc.jpg
[dobby]: https://github.com/jmpews/Dobby
[xHook]: https://github.com/iqiyi/xHook
[hellosignjni_release]: https://github.com/Hamz-a/HelloSignJNI/releases
[ghidra]: https://ghidra-sre.org/
[jeb]: https://www.pnfsoftware.com/jeb/
[recovered_code1]: /assets/files/emulating_android_native_libraries_using_unidbg/recovered_code1.jpg
[recovered_code2]: /assets/files/emulating_android_native_libraries_using_unidbg/recovered_code2.jpg
[jni_register_natives]: https://www.baeldung.com/jni-registernatives
[maven_repo]: /assets/files/emulating_android_native_libraries_using_unidbg/maven_repo.jpg
[unidbg_test_cases]: /assets/files/emulating_android_native_libraries_using_unidbg/unidbg_test_cases.jpg
[idea]: https://www.jetbrains.com/idea/
[maven]: https://maven.apache.org/
[unidbg_new_project]: /assets/files/emulating_android_native_libraries_using_unidbg/unidbg_new_project.jpg
[unidbg_create_new_module]: /assets/files/emulating_android_native_libraries_using_unidbg/unidbg_create_new_module.jpg
[unidbg_create_new_module_settings]: /assets/files/emulating_android_native_libraries_using_unidbg/unidbg_create_new_module_settings.jpg
[unidbg_create_signer_class]: /assets/files/emulating_android_native_libraries_using_unidbg/unidbg_create_signer_class.jpg
[unidbg_initial_error]: /assets/files/emulating_android_native_libraries_using_unidbg/unidbg_initial_error.jpg
[library_resolved_test_code]: https://github.com/zhkl0228/unidbg/blob/f7efc991b725af8c07feac72daa0a59bb6efb086/unidbg-android/src/test/java/com/anjuke/mobile/sign/SignUtil.java#L31-L32
[java_method_signature_guide]: https://www.microfocus.com/documentation/extend-acucobol/925/BKITITJAVAS024.html
[apktool]: https://apktool.org/
[dex2jar]: https://github.com/pxb1988/dex2jar
[dex2jar_class_method_signature]: /assets/files/emulating_android_native_libraries_using_unidbg/dex2jar_class_method_signature.jpg
[apktool_class_method_signature]: /assets/files/emulating_android_native_libraries_using_unidbg/apktool_class_method_signature.jpg
[ProxyDvmObject]: https://github.com/zhkl0228/unidbg/blob/f7efc991b725af8c07feac72daa0a59bb6efb086/unidbg-android/src/main/java/com/github/unidbg/linux/android/dvm/jni/ProxyDvmObject.java#L32
[unidbg_call_class_method_ways]: /assets/files/emulating_android_native_libraries_using_unidbg/unidbg_call_class_method_ways.jpg
[AbstractJni504]: https://github.com/zhkl0228/unidbg/blob/f7efc991b725af8c07feac72daa0a59bb6efb086/unidbg-android/src/main/java/com/github/unidbg/linux/android/dvm/AbstractJni.java#L441-L505
[unidbg_UnsupportedOperationException_1]: /assets/files/emulating_android_native_libraries_using_unidbg/unidbg_UnsupportedOperationException_1.jpg
[localdate_now]: https://docs.oracle.com/javase/8/docs/api/java/time/LocalDate.html#now--
[jeb_decompiler_localdate_now_call]: /assets/files/emulating_android_native_libraries_using_unidbg/jeb_decompiler_localdate_now_call.jpg
[app_double_check]: /assets/files/emulating_android_native_libraries_using_unidbg/app_double_check.jpg
[show_me_the_code]: https://github.com/Hamz-a/unidbg_poc_signer/