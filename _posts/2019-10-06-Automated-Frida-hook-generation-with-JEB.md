---
layout: post
title: "Automated Frida hook generation with JEB"
date: 2019-10-06 23:00:00 +0200
tags: frida android jeb
---

## Introduction
Certain mobile app pentests are done on a recurrent basis (Agile security). Some of these pentests have common repeating tasks. Since repetition is boring, we want to automate as much as possible.

In this article, I want to demonstrate how to automatically generate Frida hooks using [JEB][jeb]. The demo use case consists of generating a Frida hook to bypass the TLS pinning for [OkHttp][okhttp]. Sometimes the library is obfuscated in the target API, making hooks similar to the following unusable:

```javascript
var CertificatePinner = Java.use('okhttp3.CertificatePinner');
```

When the target APK does not obfuscate strings, it is possible to search for known strings in JEB to find the target class quickly. For OkHttp, a good magic string candidate is [**"Certificate pinning failure!"**][okhttpmagicstr]:

![okhttpmagicstrjeb][okhttpmagicstrjeb]

The process of manually searching for the magic string and adjusting the frida hook (class path + method name) could be automated using JEB's scripting API.

## JEB Script basic anatomy

It is possible to extend and/or leverage JEB's functionalities using [JEB scripts and plugins][jebscriptsplugins]. The documentation suggests scripts for *automating simple tasks*. The scripts are written in Python and saved in the **jeb_dir/scripts/** folder. [Jython][jython] is used to bridge the gap between Python and Java (JEB is a Java based app). The structure of a JEB script looks as follow:

```python
# -*- coding: utf-8 -*-
from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core import Artifact

from java.io import File

class GenerateFridaHooks(IScript):
    def run(self, ctx):
        print(u"🔥 JEB scripting")
```

The first line is used to set the encoding. When using UTF-8 strings, make sure to append the `u` prefix to your strings. Next are the imports. Notice how you can use Java imports. Finally, there's your class definition which extends `IScript`. This class has a method `run` which is obviously run everytime the script is invoked.

## JEB Script CLI vs GUI
JEB scripts can be invoked from both the desktop client or via the command line. If the script is saved in **jeb_dir/scripts/** folder, then it is possible to invoke the script by navigating to File > Scripts > Registered > *script name*.

From the command line, navigate to the JEB folder, depending on the operating system you're using, you'll need to use the appropriate bash file:
- On Windows: jeb_wincon.bat
- On Linux: jeb_linux.sh
- On Mac OSX: jeb_macos.sh

To invoke the custom plugin, use:

```bash
./jeb_macos.sh -c --srv2 --script=GenerateFridaHooks.py -- "/path/to/target.apk"
```
Everything after `--` are arguments passed to the script which can be retrieved from the context variable `ctx.getArguments()`.

JEB has the concept of Project(s) which contains Artifact(s). When an APK file is opened in the JEB desktop client, a project is created. From the command line, a project needs to be created manually. To support both CLI and GUI, we can check the instance of the context variable:

```python
def run(self, ctx):
    # Hello world
    print(u"🔥 JEB scripting")

    # If the script is run in JEB GUI
    if isinstance(ctx, IGraphicalClientContext):
        project = ctx.getMainProject()
    else:  # assume command line & create a tmp project
        argv = ctx.getArguments()
        if len(argv) < 1:
            print('[-] Did you forget to provide the APK file?')
            return
        self.inputApk = argv[0]

        # Init engine
        engctx = ctx.getEnginesContext()
        if not engctx:
            print('[-] Back-end engines not initialized')
            return

        # Create a project
        project = engctx.loadProject('JebFridaHookProject')
        if not project:
            print('[-] Failed to open a new project')
            return
        
        # Add artifact to project
        artifact = Artifact('JebFridaHookArtifact', FileInput(File(self.inputApk)))
        project.processArtifact(artifact)
```

## Processing DEX with the JEB API

A JEB project can contain several different type of files ([units][jebunits]). Since we're only interested in DEX units, it is possible to search for them specifically:

```python
# loop through all dex files in project & search
for dex in project.findUnits(IDexUnit):
    pass
```

To find the specific class and method of interest, I've opted for a naïve signature based algorithm:
1. Search for the unique magic string such as **"Certificate pinning failure!"** in OkHttp's case;
2. Get the class where the string resides and extract the class path;
3. Loop through each method of the above class, and check if the parameters matches our signature;
4. Optionally check the return value.

In the case of OkHttp, finding and hooking [`findMatchingPins(String hostname)`][findmatchingpins] could be done by simply iterating through the target class and checking if the parameter is a single String. We can do this in a modular way:

```python
def do_search(self, dex_unit, needle, params, retval = None):
    results = []
    # find string in DEX
    dex_index = dex_unit.findStringIndex(needle)
    # cross reference string, most probably used by the same class
    for ref in dex_unit.getCrossReferences(DexPoolType.STRING, dex_index):
        # get class name
        # getInternalAddress() returns something like Lcom/squareup/okhttp/CertificatePinner;->check(Ljava/lang/String;Ljava/util/List;)V+50h
        fqname = ref.getInternalAddress().split('->')[0]
        # get class (IDexClass)
        clazz = dex_unit.getClass(fqname)
        # From signature to class path
        # Lcom/squareup/okhttp/CertificatePinner; -> com.squareup.okhttp.CertificatePinner
        class2hook = clazz.getSignature()[1:-1].replace("/", ".")
        # loop through each method; check params & retval
        for method in clazz.getMethods():
            if retval is not None and method.getReturnType().getSignature() != retval: continue
            if self.list_cmp(params, [str(m.getSignature()) for m in method.getParameterTypes()]):
                method2hook = method.getName()
                results.append( {"class": class2hook, "method": method2hook})
    return results

# is there a better way? PR/PM please!
def list_cmp(self, a, b):
    if len(a) != len(b): return False
    for x, y in zip(a, b):
        if x != y: return False
    return True
``` 

The `do_search` function expects a DEX unit, a needle to search for, an array of parameters that we're looking for and optionally a return value to match against. The function returns an array of dictionaries matching the provided signature. A dictionary contains a class path and a method name.

## Putting it all together
First we'll create three variabes: an array which will contain separate Frida hooks, a Frida main template variable and an OkHttp Frida hook template:

```python
class GenerateFridaHooks(IScript):
    frida_hooks = []
    frida_hook_file = u"""'use strict';
    // Usage: frida -U -f com.example.app -l generated_hook.js --no-pause
    Java.perform(function() {\{
        {hooks}
    }
    }});
    """
    frida_okhttp3_hook = u"""
        var okhttp3_CertificatePinner{idx} = Java.use('{java_class}');
        var findMatchingPins{idx} = okhttp3_CertificatePinner{idx}.{java_method}.overload('java.lang.String');
        findMatchingPins{idx}.implementation = function(hostname) {\{
            console.log('[+] okhttp3.CertificatePinner.findMatchingPins(' + hostname + ') # {java_class}.{java_method}()');
            return findMatchingPins{idx}.call(this, ''); // replace hostname with empty string
        }}; """
```

Next, in the `run()` method, we'll add code that calls the `do_search` function with the appropriate parameters to generate our hooks:
```python
def run(self, ctx):
    # Hello world
    print(u"🔥 JEB scripting")

    # [ ... init project GUI&CLI code omitted... ]

    # loop through all dex files in project & search
    for dex in project.findUnits(IDexUnit):
        # Generating hooks for OkHttp3
        for idx, result in enumerate(self.do_search(dex, "Certificate pinning failure!", ["Ljava/lang/String;"])):
            self.frida_hooks.append(
                self.frida_okhttp3_hook.format(idx=idx, java_class=result.get("class"), java_method=result.get("method")))

    # output the Frida script
    print("-" * 100)
    print(self.frida_hook_file.format(hooks="\n".join(self.frida_hooks)))
    print("-" * 100)
```

Finally we construct the hook by concatenating them all and formatting them in the Frida main hook template. The following is a sample CLI output:

```bash
➜  jeb-pro ./jeb_macos.sh -c --srv2 --script=GenerateFridaHooks.py -- "/path/to/apk/file.apk"
<JEB startup header omitted>

🔥 JEB scripting
{JebFridaHookArtifact > JebFridaHookArtifact}: 4956 resource files were adjusted
Attempting to merge the multiple DEX files into a single DEX file...
<JEB processing omitted>
{JebFridaHookArtifact > JebFridaHookArtifact}: DEX merger was successful and produced a virtual DEX unit

🔥 Fresh Frida Hooks
----------------------------------------------------------------------------------------------------
'use strict';
    // Usage: frida -U -f com.example.app -l generated_hook.js --no-pause
    Java.perform(function() {

        var okhttp3_CertificatePinner0 = Java.use('<omitted>');
        var findMatchingPins0 = okhttp3_CertificatePinner0.a.overload('java.lang.String');
        findMatchingPins0.implementation = function(hostname) {
            console.log('[+] okhttp3.CertificatePinner.findMatchingPins(' + hostname + ') # <omitted>()');
            return findMatchingPins0.call(this, ''); // replace hostname with empty string
        };

        var okhttp3_CertificatePinner1 = Java.use('com.squareup.okhttp.CertificatePinner');
        var findMatchingPins1 = okhttp3_CertificatePinner1.findMatchingPins.overload('java.lang.String');
        findMatchingPins1.implementation = function(hostname) {
            console.log('[+] okhttp3.CertificatePinner.findMatchingPins(' + hostname + ') # com.squareup.okhttp.CertificatePinner.findMatchingPins()');
            return findMatchingPins1.call(this, ''); // replace hostname with empty string
        };

    });

----------------------------------------------------------------------------------------------------
Done.
```

Interestingly there were two instances of OkHttp library in this specific app. This is not particularly uncommon as certain dependencies might use their own instance of a library.

It might be handy to check the [DEX format][dexformat], especially when trying to come up with signatures. For example, I wanted to match methods that accept an array of *X509Certificate* & a *String* as parameter and returning *void*. `[` is used to denote an array and `V` is used to denote void:

```python
self.do_search(dex, "NEEDLE", ["[Ljava/security/cert/X509Certificate;", "Ljava/lang/String;"], "V"): # V for Void
```

Less obvious is `Z` for *boolean* though.

Checkout the code from [GitHub][jeb2frida]!


[jeb]: https://www.pnfsoftware.com
[okhttp]: https://github.com/square/okhttp
[okhttpmagicstr]: https://github.com/square/okhttp/blob/ba2c676aaf2b825528955f61dd43004a5bd9ca98/okhttp/src/main/java/okhttp3/CertificatePinner.kt#L175
[okhttpmagicstrjeb]: /assets/files/automated_frida_hook_generator_2019_10/jeb_str_search.png
[jebscriptsplugins]: https://www.pnfsoftware.com/jeb2/manual/scripts/
[jython]: https://www.jython.org
[jebunits]: https://www.pnfsoftware.com/jeb2/apidoc/reference/com/pnfsoftware/jeb/core/units/IUnit.html#subclasses-indirect
[findmatchingpins]: https://github.com/square/okhttp/blob/ba2c676aaf2b825528955f61dd43004a5bd9ca98/okhttp/src/main/java/okhttp3/CertificatePinner.kt#L208
[dexformat]: https://source.android.com/devices/tech/dalvik/dex-format#typedescriptor
[jeb2frida]: https://github.com/Hamz-a/jeb2frida