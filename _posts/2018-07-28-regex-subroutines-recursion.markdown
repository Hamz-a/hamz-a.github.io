---
layout: post
title:  "Regex subroutines and recursion"
date:   2018-07-28 15:00:00 +0200
tags: regex
---


## Introduction

Subroutines and recursion are powerful expressions that are sometimes ignored or forgotten. Maybe because the number of languages that support it are relatively scarce? If you're using PCRE, PHP which uses PCRE under the hood, Perl or Python with the [`regex`][pythonregex] module then keep reading!


## Warmup

Let's warmup with backreferences. Say you want to match the following expression `word -> word` where the left and right side are the same words. You'll usually end up using backreferences:

{% highlight text %}
([a-zA-Z0-9_]+) -> \1
{% endhighlight %}

Aside from the fact that this regex could be simplified to `(\w+) -> \1`, the regex is pretty straightforward, we use a capturing group to match a word, then reference what we have matched with `\1`. 

{% highlight text %}
foo -> foo  [ match ]
bar -> bar  [ match ]
qux -> baz  [ won't match ]
baz qux     [ won't match ]
{% endhighlight %}

But what if we don't want to match the exact word but *reuse* the capturing group?


## Subroutines

Continuing with our previous example, say we want to match instances such as `qux -> baz`, usually we would write the following expression:

{% highlight text %}
[a-zA-Z0-9_]+ -> [a-zA-Z0-9_]+
{% endhighlight %}

Good so far but we can do better. With subroutines we can reuse defined groups:

{% highlight text %}
([a-zA-Z0-9_]+) -> (?1)
{% endhighlight %}

The expression above matches a word, puts it in group #1, then reuses the expression in group #1 with `(?1)`. The results: 

{% highlight text %}
foo -> foo  [ match ]
bar -> bar  [ match ]
qux -> baz  [ match ]
baz qux     [ won't match ]
{% endhighlight %}

There are different variations of subroutines:
- `(?1)` will call group #1, effectively if you have group #2 you can also use `(?2)` and so on.
- `(?+1)` will call the next group. Using our example above, we could rewrite it as: `(?+1) -> ([a-zA-Z0-9_]+)`. Of course, using `(?+2)` is also possible if the second next group exists and so on.
- `(?-1)` same as above but will call the previous group. Using our example above, we could rewrite is as: `([a-zA-Z0-9_]+) -> (?-1)`.
- `(?&name)` also known as named subroutines. Using our example above, we could rewrite is as: `(?P<word>[a-zA-Z0-9_]+) -> (?&word)`.


## Realword subroutine example

Say we want to match [UUID][uuidwiki]'s. UUID's are 32 hexadecimal characters separated by hyphens adhering the following pattern: `8-4-4-4-12`. The vanilla regex pattern would look like this:

{% highlight text %}
[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}
{% endhighlight %}

Let's use subroutines instead. As we can see the basic unit is 4 hex characters, let's use that as a basis and complete the pattern:

{% highlight text %}
([a-fA-F0-9]{4})(?1)-(?1)-(?1)-(?1)-(?1){3}
{% endhighlight %}

Much shorter! We can go a step further by repeating this part `4-4-4` to make it even more shorter:

{% highlight text %}
([a-fA-F0-9]{4})(?1)(-(?1)){3}-(?1){3}
{% endhighlight %}

Now that's a bad idea since regexes are hard to read to begin with for most people. It's better to make it as readable as possible. We can achieve this by using the `x` modifier to allow for whitespaces in our regex. This also has the advantage that we can add comments. We'll also use named groups instead:

{% highlight text %}
(?P<hex>[a-fA-F0-9]{4})(?&hex) # 8 hex combo
-(?&hex)-(?&hex)-(?&hex)       # 4-4-4 hex combo
-(?&hex){3}                    # 12 hex combo
{% endhighlight %}


## Recursion

Now recursion is basically a subroutine that calls itself. The most common example is to match balanced brackets: 

{% highlight text %}
\{                 # Match opening tag
    (?:            # Non capturing-group
        [^{}]      # Match anything that's not an opening or closing tag
        |          # Else (which means we encountered an opening or closing tag)
        (?R)       # Recurse the whole pattern
    )*             # Repeat zero or more times, we could also use + instead of * if we don't want to match empty tags
\}                 # Match close tag
{% endhighlight %}

Worth noting that `(?R)` is the same as `(?0)` since group #0 is basically the whole pattern. Some test cases:

{% highlight text %}
{% raw %}
foo          [ won't match ]
{}           [ match ]
{foo}        [ match ]
{{ bar }}    [ match ]
{{{ baz }}}  [ match ]
{% endraw %}
{% endhighlight %}


## (?(DEFINE)) trick

There's a trick worth noting which is the DEFINE trick. I think it's easiest if we reference directly from the [PCRE manual][pcreman]:


{% highlight text %}
 Defining subpatterns for use by reference only

       If  the  condition  is  the string (DEFINE), and there is no subpattern
       with the name DEFINE, the condition is  always  false.  In  this  case,
       there  may  be  only  one  alternative  in the subpattern. It is always
       skipped if control reaches this point  in  the  pattern;  the  idea  of
       DEFINE  is that it can be used to define subroutines that can be refer-
       enced from elsewhere. (The use of subroutines is described below.)  For
       example,  a  pattern  to match an IPv4 address such as "192.168.23.245"
       could be written like this (ignore white space and line breaks):

         (?(DEFINE) (?<byte> 2[0-4]\d | 25[0-5] | 1\d\d | [1-9]?\d) )
         \b (?&byte) (\.(?&byte)){3} \b

       The first part of the pattern is a DEFINE group inside which a  another
       group  named "byte" is defined. This matches an individual component of
       an IPv4 address (a number less than 256). When  matching  takes  place,
       this  part  of  the pattern is skipped because DEFINE acts like a false
       condition. The rest of the pattern uses references to the  named  group
       to  match the four dot-separated components of an IPv4 address, insist-
       ing on a word boundary at each end.
{% endhighlight %}

Basically we can put all kinds of patterns inside the DEFINE area and use it later on in our regex. Back to the UUID example, we could write:

{% highlight text %}
(?(DEFINE)                     # regex definitions
    (?P<hex>[a-fA-F0-9]{4})    # match 4 hex chars
)
# Matching starts now...
(?&hex){2}                     # 8 hex combo
-(?&hex)-(?&hex)-(?&hex)       # -4-4-4 hex combo
-(?&hex){3}                    # -12 hex combo
{% endhighlight %}

## Combining everything in the real world

Say we have developed our own syntax which resembles JSON in some sense:

{% highlight text %}
{
  foo : bar,
  baz : [aa, bb, ccc],
  123 : 123,
  obj : { foo : bar}
}
{% endhighlight %}

If want to validate such syntax we'll need recursion too since an object can in itself contain another object:

{% highlight text %}
(?(DEFINE)                     # regex definitions
    (?P<string>[a-zA-Z0-9]+)
    (?P<value>\s*(?:(?&string)|(?&array)|(?&object))\s*)
    (?P<array>\s*\[\s*(?&value)\s*(?:\s*,\s*(?&value)\s*)*\])
    (?P<pair>(?&string)\s*:\s*(?&value))
    (?P<object>\{\s*(?&pair)\s*(?:\s*,\s*(?&pair)\s*)*\})
)
(?&object)
{% endhighlight %}

The above regex can be found online on [regex101][regex101], an awesome online regex fiddler. Make sure to select the right language on the left and set the right regex modifier.

This [StackOverflow thread][sojsonregex] took it to the next level by validating JSON entirely with regex.

The techniques described here are probably useful, but in general you either want to use a full-fledged parser or use one of the standard libraries of your programming environment. For example, to validate JSON strings, you could load it with your favorite function/library. It will probably throw an exception if it's invalid :\_)


[pythonregex]: https://pypi.org/project/regex/
[uuidwiki]: https://en.wikipedia.org/wiki/Universally_unique_identifier
[pcreman]: http://www.pcre.org/pcre.txt
[jsonrfc]: https://tools.ietf.org/html/rfc7159#section-2
[antlrjson]: https://github.com/antlr/grammars-v4/blob/master/json/JSON.g4
[json.org]: https://json.org/
[sojsonregex]: https://stackoverflow.com/questions/2583472/regex-to-validate-json
[regex101]: https://regex101.com/r/5ST4kW/1