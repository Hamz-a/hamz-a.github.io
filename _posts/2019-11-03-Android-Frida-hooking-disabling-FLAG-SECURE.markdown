---
layout: post
title: "Android Frida hooking: disabling FLAG_SECURE"
date: 2019-11-03 22:00:00 +0200
tags: frida android flag secure
--- 

## Introduction
In Android land, it is possible to protect specific components (ex: activities) from being screenshotted. This is achieved by adding the [`FLAG_SECURE`][FLAG_SECURE] flag on the desired component:

> FLAG_SECURE
>
> public static final int FLAG_SECURE
>
> Window flag: treat the content of the window as secure, preventing it from appearing in screenshots or from being viewed on non-secure displays.

A typical implementation from the app's perspective looks as follows:

```java
// https://stackoverflow.com/a/9822607
public class FlagSecureTestActivity extends Activity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);

        setContentView(R.layout.main);
    }
}
```

This means that if we want to be able to take a screenshot, we need to disable this feature. In this blogpost I'll demonstrate a few Frida hooking techniques and patterns along the way to achieve this goal.

> Note: In Android, there's also a `SurfaceView` which has the method `setSecure()`. The techniques explained here should also work for `SurfaceView`s.


## The usual hooking pattern

I've noticed that most hooks try to disable the `FLAG_SECURE` attribute by hooking the `setFlags()` function. Instead of adding the `FLAG_SECURE` flag, it is removed.  Below is a sample [xposed hook][xposed_hook]:

```java
@Override
public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
    // Hook into "setFlags" method in the "Window" class, and replace it with our custom setFlags method
    XposedHelpers.findAndHookMethod(Window.class, "setFlags", int.class, int.class, mRemoveSecureFlagHook);
}

// Custom setFlags hook
private final XC_MethodHook mRemoveSecureFlagHook = new XC_MethodHook() {
    @Override
    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
        Integer flags = (Integer) param.args[0]; // Get current state of flags
        flags &= ~WindowManager.LayoutParams.FLAG_SECURE; // Substract the FLAG_SECURE value
        param.args[0] = flags; // Update it
    }
};
```

In Frida, this looks as follows:

```javascript
1. Java.perform(function () {
2.     // https://developer.android.com/reference/android/view/WindowManager.LayoutParams.html#FLAG_SECURE
3.     var FLAG_SECURE = 0x2000;
4.     var Window = Java.use("android.view.Window");
5.     var setFlags = Window.setFlags;  //.overload("int", "int")
6.
7.     setFlags.implementation = function (flags, mask) {
8.         console.log("Disabling FLAG_SECURE...");
9.         flags &= ~FLAG_SECURE;
10.        setFlags.call(this, flags, mask);
11.        // Since setFlags returns void, we don't need to return anything
12.    };
13. });
```

1. In (3) we define a `FLAG_SECURE` variable, this flag is a constant and can be found in the documentation (2).
2. In (4) we create a bridge to interface with the `Window` Android class
3. In (5) we create a bridgee to interface with the `setFlags` method. Note that if this method had several overloads, it would have been necessary to specify which overload to choose by using `var setFlags = Window.setFlags.overload("int", "int");`. In this case, since there's only one method called `setFlags` in the `Window` class, it is not nessecary.
4. In (7) we hook the `setFlags` method with our own implementation.
5. In (9) we modify the `flags` variable by substracting the `FLAG_SECURE` flag. These are basic bitwise operations in one line.
6. In (10) we finally call the original `setFlags` method with the modified `flags` value (ie: with no `FLAG_SECURE` flag).

The application can then be spawned as follows:

```bash
frida -U -l usual_flagsecure_disable.js -f com.example.app --no-pause

     ____
    / _  |   Frida 12.7.11 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/
Spawned `com.example.app`. Resuming main thread!
[Xiaomi Mi A2::com.example.app]-> Disabling FLAG_SECURE...
Disabling FLAG_SECURE...
Disabling FLAG_SECURE...
Disabling FLAG_SECURE...
```

## When the app is already running...

The above hook is used when spawning an app. This means that our hook can intercept the target function on time. But what if the app is already running and we try to attach to the app? Well since the activity is already initialized, the target function will not be called and therefore our hook will not get triggered. How do we proceed further?

With Frida, we can scan the heap for objects (class instances) with the `Java.choose()` method:

```javascript
Java.perform(function() {
    Java.choose("com.example.app.FlagSecureTestActivity", {
        "onMatch": function (instance) {
            console.log("Found instance of FlagSecureTestActivity: " + instance);
        },
        "onComplete": function () {
        }
    });
});
```

With this we can access the `Window` object from within the activity!

```javascript
Java.perform(function() {
    Java.choose("com.example.app.FlagSecureTestActivity", {
        "onMatch": function (instance) {
            console.log("Found instance of FlagSecureTestActivity: " + instance);
            console.log(instance.getWindow());
        },
        "onComplete": function () {
        }
    });
});
```

Now what if we try to call the `setFlags()` from the `Window` object?
```javascript
Java.perform(function() {
    var FLAG_SECURE = 0x2000;

    Java.choose("com.example.app.FlagSecureTestActivity", {
        "onMatch": function (instance) {
            console.log("Found instance of FlagSecureTestActivity: " + instance);
            console.log(instance.getWindow());
            instance.getWindow().setFlags(0, FLAG_SECURE);
        },
        "onComplete": function () {
        }
    });
});
```

Notice we use `-n` to attach to the app instead of spawning:
```bash
frida -U -l run_flagsecure_disable.js -n com.example.app --no-pause
     ____
    / _  |   Frida 12.7.11 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/
Attaching...

Found instance of FlagSecureTestActivity: com.example.app.FlagSecureTestActivity@3cb1848

com.android.internal.policy.PhoneWindow@aedcd6f

Error: android.view.ViewRootImpl$CalledFromWrongThreadException: Only the original thread that created a view hierarchy can touch its views.
    at frida/node_modules/frida-java-bridge/lib/env.js:120
    at input:1
    at /run_flagsecure_disable.js:49
    at chooseObjectsArtModern (frida/node_modules/frida-java-bridge/lib/class-factory.js:42)
    at frida/node_modules/frida-java-bridge/lib/class-factory.js:153
    at ve (frida/node_modules/frida-java-bridge/lib/android.js:377)
[Xiaomi Mi A2::com.example.app]->
```

This results into an interesting error message: **Only the original thread that created a view hierarchy can touch its views.**

The first Google search result brings us to this [Stackoverflow thread][so_thread] which suggest to move the code responsible for UI changes on the UI thread by calling [`Activity.runOnUiThread()`][activity_runonuithread]:

```java
runOnUiThread(new Runnable() {
    @Override
    public void run() {
        // Change UI
    }
});
```

So how do we implement above Java code with Frida? We need a custom implementation of the `Runnable` interface. Luckily we can create custom classes in Frida too using the `Java.registerClass()` method:

```javascript
1. Java.perform(function() {
2.     // https://developer.android.com/reference/android/view/WindowManager.LayoutParams.html#FLAG_SECURE
3.     var FLAG_SECURE = 0x2000;
4.
5.     var Runnable = Java.use("java.lang.Runnable");
6.     var DisableSecureRunnable = Java.registerClass({
7.         name: "me.bhamza.DisableSecureRunnable",
8.         implements: [Runnable],
9.         fields: {
10.             activity: "android.app.Activity",
11.         },
12.         methods: {
13.             $init: [{
14.                 returnType: "void",
15.                 argumentTypes: ["android.app.Activity"],
16.                 implementation: function (activity) {
17.                     this.activity.value = activity;
18.                 }
19.             }],
20.             run: function() {
21.                 var flags = this.activity.value.getWindow().getAttributes().flags.value; // get current value
22.                 flags &= ~FLAG_SECURE; // toggle it
23.                 this.activity.value.getWindow().setFlags(flags, FLAG_SECURE); // disable it!
24.                 console.log("Done disabling SECURE flag...");
25.             }
26.         }
27.     });
28.
29.     Java.choose("com.example.app.FlagSecureTestActivity", {
30.         "onMatch": function (instance) {
31.             var runnable = DisableSecureRunnable.$new(instance);
32.             instance.runOnUiThread(runnable);
33.         },
34.         "onComplete": function () {}
35.     });
36. });
```

1. Whenever trying to hook on the Java layer, we need to encapsulate our hooking code in `Java.perform(function() {});` (1).
2. We create a bridge to interface with the `Runnable` class (5).
3. We create our own custom class (6), give it a name (7) and specify that it implements the `Runnable` interface (8).
4. Since we need a reference to the activity we want to hook, we add a new field called `activity` (9-11). We will "inject" the target activity via the constructor (13).
5. We implement our own methods (12), the first one being our constructor which is denoted with `$init` (13) and the second one being `run` (14) to conform to the `Runnable` interface.
6. Our custom `run` method will contain logic to edit the `flags` value and remove the `FLAG_SECURE` flag (20-25).
7. From line (29), we'll do the same as mentioned previously, scan the heap for an instance of the target activity, if there's a match (30), we'll instantiate an instance of our custom `Runnable` class (31) and call the `runOnUiThread()` method with it.

Launching the app and then attaching our hook gives us the following result:
```bash
frida -U -l run_flagsecure_disable.js -n com.example.app --no-pause
     ____
    / _  |   Frida 12.7.11 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/

[Xiaomi Mi A2::com.example.app]-> Done disabling SECURE flag...
```
It is now possible to take screenshots on the opened activity.

## fah screen

Above hook is actually part of a tool [Frida Android Helper][fah_github]; a side project to automate certain repetitive tasks during mobile app pentests. By invoking `fah screenshot` command, the tool will try to take a screenshot via the ADB `screencap` command. If this fails, the current opened app and activity is fetched with some ADB/grep-fu:

```python
def get_current_app_focus(device: Device):
    # Sample: mCurrentFocus=Window{127ced0 u0 com.android.launcher3/com.android.searchlauncher.SearchLauncher}
    # When locked: mCurrentFocus=Window{8f41b66 u0 StatusBar}
    result = perform_cmd(device, "dumpsys window windows | grep mCurrentFocus")

    currentFocus = result.strip("\r\n{}").split(" ")[-1]
    if "/" in currentFocus:
        return currentFocus.split("/")
    else:
        print("⚠️  Device might be locked... (mCurrentFocus={})".format(currentFocus))
        return [currentFocus, ""]
```

The result (app ID + path to activity class) is passed to another function which sets Frida up, attaches to the app using the app ID, injects our hook and sends an RPC command with the activity to hook:

```python
def disable_secure_flag(device, pkg_name, activity_name):
    js_code = get_js_hook("disable_secure_flag.js")
    device = frida.get_device(device.get_serial_no())
    session = device.attach(pkg_name)
    script = session.create_script(js_code)
    script.on("message", message_callback)
    script.load()
    script.exports.disablesecureflag(activity_name)
```

The previously written Frida script is wrapped around an [RPC call][rpc_call] which can be called from the Python side. For more information see [Frida RPC][frida_rpc] and the [Frida Android Helper source code][fah_github].

![fah_screen][fah_screen]


[FLAG_SECURE]: https://developer.android.com/reference/android/view/WindowManager.LayoutParams.html#FLAG_SECURE
[xposed_hook]: https://github.com/veeti/DisableFlagSecure/blob/fd8833a10a1544324f3301f647e74beee9cac58a/src/main/java/fi/veetipaananen/android/disableflagsecure/DisableFlagSecureModule.java
[so_thread]: https://stackoverflow.com/questions/5161951/android-only-the-original-thread-that-created-a-view-hierarchy-can-touch-its-vi
[activity_runonuithread]: https://developer.android.com/reference/android/app/Activity.html#runOnUiThread(java.lang.Runnable)
[fah_github]: https://github.com/Hamz-a/frida-android-helper
[rpc_call]: https://github.com/Hamz-a/frida-android-helper/blob/b4a0497695e96b0d32db45396ed66a2afe250b23/frida_android_helper/frida_hooks/disable_secure_flag.js
[frida_rpc]: https://www.frida.re/docs/javascript-api/#rpc
[fah_screen]: /assets/files/android_frida_hooking_disabling_flag_secure_2019_11/fah_screen.png