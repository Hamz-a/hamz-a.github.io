---
layout: post
title:  "Regex tricks"
date:   2018-09-16 14:00:00 +0200
tags: regex
categories: blogpost
---

Modern regex engines have some powerful features which are not used quite often. Maybe because regexes are considered cryptic and hard to begin with? In this blogpost I want to document a few of my favourite tricks.


# The `x` modifier
The `x` modifier is a good way to make your cryptic regexes more readable. If this modifier is set, whitespace characters are ignored in the pattern. Everything after `#` is ignored as well. This means that you can write your regex on several lines while adding comments on each line.

Say for example you want to write a validation regex in PHP for a custom ID, it might look something like this:

{% highlight php %}
$regex_id = '/     # Delimiter
^                  # Start of string
[a-z]{4}           # Followed by 4 letters
_                  # Followed by an underscore
[0-9]{6}           # Followed by 6 digits
$                  # End of string
/x'; // the x modifier
{% endhighlight %}

Keep in mind that if you need to match a literal space or a number sign `#` you will need to escape them or put them in a character class:

{% highlight php %}
$regex_id = '/     # Delimiter
^                  # Start of string
\#?                # Optional "#"
[a-z]{4}           # Followed by 4 letters
\ ?                # Optional space
_                  # Followed by an underscore
[ ]?               # Optional space
[0-9]{6}           # Followed by 6 digits
[#]?               # Optional "#"
$                  # End of string
/x'; // the x modifier
{% endhighlight %}

Check it out on [regex101][regex101_xmodifer].

# The `\K` escape sequence
Let's say we want to match `helloworld` that is preceded with `foo` somewhere in the string. Most regex engines do not support arbitrary lookbehinds. See output of the following php code:

{% highlight shell %}
➜  ~ php -r "preg_match('/(?<=foo.*?)helloworld/', 'foo bar baz helloworld');"

Warning: preg_match(): Compilation failed: lookbehind assertion is not fixed length at offset 10 in Command line code on line 1
{% endhighlight %}

The `\K` escape sequence can be a nice workaround to this problem. When this sequence is used in a regex, you're basically telling the regex engine to "forget" what has been matched so far. The above example can be rewritten as such:

{% highlight php %}
<?php

$regex = '/foo.*?\Khelloworld/';
$input = 'foo bar baz helloworld';
preg_match_all($regex, $input, $m);
var_dump($m[0]);

/* output:
array(1) {
  [0]=>
  string(10) "helloworld"
}*/
{% endhighlight %}

The only downside to this technique is that it "consumes" what we have matched so far, meaning that we won't be able to have overlapping matches. Say we have the following input string:

{% highlight text %}
foo bar baz helloworld test helloworld
{% endhighlight %}

The following steps happen roughly inside the regex engine:

{% highlight text %}
foo bar baz helloworld test helloworld
^^^^^^^^^^^^
^           ^^^^^^^^^^- matched by helloworld
^- matched by foo.*?

foo bar baz helloworld test helloworld
                      ^ engine now continues from here, no more "foo" to be found...
{% endhighlight %}

The first match consumed a part of the string. The engine continues from where it left to find another match. However no more `foo` is to be found, therefore the second `helloworld` does not get matched.

# `(*SKIP)` & `(*FAIL)` trick
Perl and PCRE-enabled engines support "Backtracking Control Verbs" which are extensively covered on [rexegg][backtrackcontrolverbs]. I want to cover a simple yet powerful trick which combines two of these control verbs. Say you want to match all instances of `hello\d+` but it should not be enclosed in brackets `<>`. This is easily achieved using SKIP & FAIL:

{% highlight php %}
<?php

$regex = '/
<.*?>            # Match all instances of <.....>
(*SKIP)(*FAIL)   # Skip all those matches and make them fail
|                # Or...
hello\d+         # Match hello followed by digits
/x';
$input = '<foo hello1> hello2 <hello3> hello4';
preg_match_all($regex, $input, $m);
var_dump($m[0]);

/* output:
array(2) {
  [0]=>
  string(6) "hello2"
  [1]=>
  string(6) "hello4"
}*/
{% endhighlight %}

Without going too much into the internal workings of `(*SKIP)` & `(*FAIL)`, you can use this combination `/pattern1(*SKIP)(*FAIL)|pattern2/` to instruct the regex engine to match `pattern2` while excluding `pattern1`.

If you're interested how this trick exactly works, make sure to check out the [rexegg article][skipfail].


[regex101_xmodifer]: https://regex101.com/r/KA2N9e/1
[backtrackcontrolverbs]: http://www.rexegg.com/backtracking-control-verbs.html
[skipfail]: http://www.rexegg.com/backtracking-control-verbs.html#skipfail