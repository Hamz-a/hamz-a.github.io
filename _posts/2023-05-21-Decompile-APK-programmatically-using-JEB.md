---
layout: post
title: "Decompile APK programmatically using JEB"
date: 2023-05-21 22:00:00 +0200
tags: android jeb
categories: blogpost
--- 

## Introduction
For a project, I needed to decompile programmatically certain classes from an Android APK file. Usually this is done by first extracting the DEX file using [apktool][apktool], then converting it to a JAR file using [dex2jar][dex2jar], and finally decompiling it using tools like [JAD][jad] or [CFR][cfr].

In order to compare results from various decompilers, I wanted to add [JEB decompiler][jebdec] to the mix. JEB provides a scripting interface and allows scripts to be executed either through [CLI or GUI][jebclivsgui].

## Sample default decompilation script
A good thing about JEB is that it provides several template scripts under:

> INSTALL_DIR/scripts/samples

One particular script stood out, as its name implies [`DecompileFile.py`][decompilefile.py]. The class contains two methods: a default `run` method which is the entry point of the script and a `decompileCodeUnit` method.

### Run method explained

The `run` method performs the following:

1) Has two flags to decompile DEX or native units (or not)
```python
self.decompileDex = False
self.decompileNative = False
```

2) Checks if the script is run from CLI or GUI to setup required arguments
```python
if isinstance(ctx, IGraphicalClientContext):
  self.outputDir = ctx.displayFolderSelector('Output folder')
  if not self.outputDir:
    print('Need an output folder')
    return
else:
  argv = ctx.getArguments()
  if len(argv) < 2:
    print('Provide an input file and the output folder')
    return
  inputFile = argv[0]
  self.outputDir = argv[1]
  print('Processing file: %s...' % inputFile)
  ctx.open(inputFile)
```

3) Iterates through [code units][codeunits] and calls the `decompileCodeUnit` per code unit
```python
prj = ctx.getMainProject()
assert prj, 'Need a project'

t0 = time.time()
print('Exectime: %f' % exectime)
```

### decompileCodeUnit explained

The `decompileCodeUnit` subsequently accepts a code unit and performs the following:

1) Checks if the unit is processed, if not, then process it
```python
if not codeUnit.isProcessed():
  if not codeUnit.process():
    print('The code unit cannot be processed!')
    return
```

2) In JEB, each unit type (bytecode, binary code, etc...) has its own decompiler, therefore a helper is used to retrieve the appropriate helper
```python
decomp = DecompilerHelper.getDecompiler(codeUnit)
if not decomp:
  print('There is no decompiler available for code unit %s' % codeUnit)
  return
```

3) Output folder is designated and some filtering is applied depending on flags defined previously
```python
outdir = os.path.join(self.outputDir, codeUnit.getName() + '_decompiled')
print('Output folder: %s' % outdir)  # created only if necessary, i.e. some contents was exported

if not((isinstance(codeUnit, INativeCodeUnit) and self.decompileNative) or (isinstance(codeUnit, IDexUnit) and self.decompileDex)):
  print('Skipping code unit: %s' % UnitUtil.buildFullyQualifiedUnitPath(codeUnit))
  return
```

4) Next, a [`DecompilerExporter`][decompilerexporter] object is created. Probably the most interesting part of this script as several options can be configured including:
1. an output folder for where to save the decompiled code.
2. a timeout for method decompilation.
3. a timeout for the entire decompilation process.
4. a [progress callback][progresscallback], useful to log for example the progress of the decompilation process.

```python
exp = decomp.getExporter()
exp.setOutputFolder(IO.createFolder(outdir))
exp.setMethodTimeout(1 * 60000)
exp.setTotalTimeout(15 * 60000)
class DecompCallback(ProgressCallbackAdapter):
  def message(self, msg):
    print('%d/%d: %s' % (self.getCurrent(), self.getTotal(), msg))
exp.setCallback(DecompCallback())
```

5) Finally, the decompilation is kickstarted. Good to know is that [`export`][export] is a synonym to [`process`][process]
```python
if not exp.export():
  cnt = len(exp.getErrors())
  i = 1
  for sig, err in exp.getErrors().items():
    print('%d/%d DECOMPILATION ERROR: METHOD %s: %s' % (i, cnt, sig, err))
    i += 1
```

## Tweaking the script
The provided template is a good start. I needed to introduce a few tweaks for my needs.

1) The first of which is to enable decompilation for DEX
```python
self.decompileDex = True
self.decompileNative = False
```

2) For relatively huge apps, I needed to remove the timeout for the total decompilation process
```python
# DecompilerExporter object
exp = decomp.getExporter()
exp.setOutputFolder(IO.createFolder(outdir))
# limit to 1 minute max per method
exp.setMethodTimeout(1 * 60000)
# limit to 15 minutes (total)
# exp.setTotalTimeout(2 * 60000)
```
I left the method timeout in case a method is too big/complex.

3) Since the target app is relatively big and I only needed specific packages to be decompiled, I added a pattern matcher using the [`setSignaturePattern`][setsignaturepattern] method. It accepts a compiled regex using a [`Pattern`][pattern] object.

```python
from java.util.regex import Pattern
# ... omitted ...
pattern = Pattern.compile(".*/(cash|ali).*")
exp.setSignaturePattern(pattern)
# set a callback to output real-time information about what's being decompiled
class DecompCallback(ProgressCallbackAdapter):
  def message(self, msg):
    print('%d/%d: %s' % (self.getCurrent(), self.getTotal(), msg))
exp.setCallback(DecompCallback())
# decompile & export
if not exp.export(): # process
```

## Concluding
Without the introduced tweaks, the script would timeout and barely decompile anything interesting. Commenting out the timeout for the entire decompilation process solved that problem. However, the decompilation took forever on my target app and eventually led to JEB crashing. Luckily, there's a way to reduce the amount of work by matching only classes/methods that are of interest.

The final customized script can be found on [GitHub][gh_custom_script]. It can be placed under the scripts folder and called from GUI, or from the CLI:

```
~/tools/jeb/jeb_macos.sh -c --srv2 --script=/path/to/DecompileFileCustom.py -- /path/to/base.apk /path/to/decompile/folder
```


[apktool]: https://ibotpeaches.github.io/Apktool/
[dex2jar]: https://github.com/pxb1988/dex2jar
[jad]: http://www.javadecompilers.com/jad
[cfr]: https://www.benf.org/other/cfr/
[jebdec]: https://www.pnfsoftware.com/jeb/
[jebclivsgui]: /blogpost/2019/10/06/Automated-Frida-hook-generation-with-JEB.html#jeb-script-cli-vs-gui
[decompilefile.py]: https://github.com/pnfsoftware/jeb-samplecode/blob/master/scripts/DecompileFile.py
[codeunits]: https://www.pnfsoftware.com/jeb/apidoc/reference/com/pnfsoftware/jeb/core/units/code/ICodeUnit.html
[decompilerexporter]: https://www.pnfsoftware.com/jeb/apidoc/reference/com/pnfsoftware/jeb/core/units/code/DecompilerExporter.html
[progresscallback]: https://www.pnfsoftware.com/jeb/apidoc/reference/com/pnfsoftware/jeb/util/base/IProgressCallback.html
[export]: https://www.pnfsoftware.com/jeb/apidoc/reference/com/pnfsoftware/jeb/core/units/code/DecompilerExporter.html#export()
[process]: https://www.pnfsoftware.com/jeb/apidoc/reference/com/pnfsoftware/jeb/core/units/code/DecompilerExporter.html#process()
[pattern]: https://docs.oracle.com/javase/8/docs/api/java/util/regex/Pattern.html
[setsignaturepattern]: https://www.pnfsoftware.com/jeb/apidoc/reference/com/pnfsoftware/jeb/core/units/code/DecompilerExporter.html#setSignaturePattern(java.util.regex.Pattern)
[gh_custom_script]: https://github.com/Hamz-a/hamz-a.github.io/blob/master/assets/files/decompile_apk_programmatically_using_jeb/DecompileFileCustom.py
