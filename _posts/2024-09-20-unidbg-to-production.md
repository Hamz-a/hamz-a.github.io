---
layout: post
title: "Unidbg to production"
date: 2024-09-20 20:00:00 +0200
tags: android reverse engineering unidbg spring-boot
categories: blogpost
image: /assets/files/unidbg-to-production/og_social.jpg
--- 

## Introduction
In [the last blogpost][last_blog_post], we covered how to use [unidbg][unidbg_github] from scratch to emulate an Android native library. As some might have noticed, the Proof of Concept code is not production ready as it does not allow for a way to call the signing functionality externally. More importantly, the code is too slow for practical use. Let's add some time measuring code to our [previous main method][previous_main_method] to see this in action:

```java
public class Main {
    public static void main(String[] args) {
        long start = System.currentTimeMillis();
        Signer signer = new Signer("/tmp/libhellosignjni.so");

        String signature = signer.sign("helloworld");
        System.out.println("Signature: " + signature);

        long end = System.currentTimeMillis();
        System.out.println("Total execution time : " + ((end - start) / 1000.0) + " seconds");
    }
}
```

Running the above code takes more than 6 seconds for a single signature (on a decent modern computer)!
```
Signature: c24e48124f5c69ec647a5147193932f2a7aef0a9362163ce0ca29da259b2047c
Total execution time : 6.483 seconds
```

In this blogpost, we'll cover how to make unidbg usable for production by pointing out the bottleneck in execution. In addition, we'll add a layer around unidbg to expose the signing functionality to other services.

## The bottleneck
After debugging the code, it is pretty obvious which part of the code takes the longest to run. See the [updated code snippet][updated_code_snippet]:
```java
public class Main {
    public static void main(String[] args) {
        long t1 = System.currentTimeMillis();
        Signer signer = new Signer("/tmp/libhellosignjni.so");

        long t2 = System.currentTimeMillis();
        System.out.println("Execution time for initialization: " + ((t2 - t1) / 1000.0) + " seconds");

        String signature = signer.sign("helloworld");
        System.out.println("Signature: " + signature);
        long t3 = System.currentTimeMillis();

        System.out.println("Execution time for signing: " + ((t3 - t2) / 1000.0) + " seconds");
    }
}
```

Running the above code results into the following output:
```
Execution time for initialization: 6.258 seconds
Signature: c24e48124f5c69ec647a5147193932f2a7aef0a9362163ce0ca29da259b2047c
Execution time for signing: 0.041 seconds
```

We can conclude that what takes the longest is initializing and setting up the emulator, whereas the signing call only takes a fraction of a second. This is good news, since this means we can create a service where we initialize the emulator object once, and subsequent signing requests will be handled directly without the setup overhead.

## Signing as a Service
Emulating the signing procedure is cool but we need to provide a programmatic interface for other applications to integrate with our unidbg signing service. There are many options, but for simplicity's sake, we'll create an HTTP API endpoint using [Spring boot][springboot].

After [adding the Spring boot dependency to our `pom.xml` file][update_pom], we create the main Spring boot application:
```java
package me.bhamza.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringUnidbgSignerApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringUnidbgSignerApplication.class, args);
    }
}
```

Next, let's create our [Spring Service][springservice]:
```java
package me.bhamza.example;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class SignerService {
    private Signer unidbgSigner;

    public SignerService(@Value("${so-file}") String so_file) {
        this.unidbgSigner = new Signer(so_file);
    }

    String sign(String message) {
        return this.unidbgSigner.sign(message);
    }
}
```
The [`Value` annotation][springvalue] is used to automatically inject the `so_file` value which represents the path to the `.so` file we want to emulate. We can define this value by creating an `application.properties` file under the `resources` folder:
```
spring.application.name=unidbgsigner
so-file=/tmp/libhellosignjni.so
```

Finally, let's create a controller for our signing endpoint:
```java
package me.bhamza.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class SignerController {
    @Autowired
    public SignerService signerService;

    @GetMapping("/")
    public String index() {
        return "Hello signer!";
    }

    @RequestMapping(path = "/sign", consumes = MediaType.APPLICATION_JSON_VALUE, method = {RequestMethod.POST})
    public String sign(@RequestBody Map<String, String> payload) {
        return signerService.sign(payload.getOrDefault("message", ""));
    }
}
```

[`@AutoWired`][springautowired] is used to inject our unidbg signing service. Upon starting the Spring boot application, the service is instantiated. This might take a few seconds, but only on startup!

## Test it out
Let's run it and test it out:
![runit][runit]

A quick curl command to confirm it is working!
```
curl -H "Content-Type: application/json" --request POST --data '{"message":"hellosign"}' http://localhost:8080/sign

c15991f870f43089493b8750718e0b88e7d020e6018a7faa73b8e21f609859a6
```

Check out the final [source code here][show_me_the_code].<br>
Do you have questions? Want to see more? DM me.


[last_blog_post]: /blogpost/2024/09/10/Emulating-Android-native-libraries-using-unidbg.html
[unidbg_github]: https://github.com/zhkl0228/unidbg
[previous_main_method]: https://github.com/Hamz-a/unidbg_poc_signer/blob/906cf2669e44c8929d3c5898c1d4e670433b26b5/src/main/java/me/bhamza/example/Main.java
[updated_code_snippet]: https://github.com/Hamz-a/unidbg_poc_signer/commit/1c3a439a9d605365a1b2a987d951defb857d24f3
[update_pom]: https://github.com/Hamz-a/unidbg_poc_signer/commit/334ed45cb812553218effbfbc4458a5a1bc4addc
[springboot]: https://spring.io/projects/spring-boot
[springservice]: https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/stereotype/Service.html
[springvalue]: https://docs.spring.io/spring-framework/reference/core/beans/annotation-config/value-annotations.html
[springautowired]: https://docs.spring.io/spring-framework/reference/core/beans/annotation-config/autowired.html
[runit]: /assets/files/unidbg-to-production/runit.jpg
[show_me_the_code]: https://github.com/Hamz-a/unidbg_poc_signer