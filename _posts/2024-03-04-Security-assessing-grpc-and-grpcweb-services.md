---
layout: post
title: "Security assessing gRPC & gRPC-web services"
date: 2024-03-04 9:00:00 +0200
tags: grpc web burp extension
categories: blogpost
image: /assets/files/security_assessing_grpc_and_grpcweb_services/og_social.png
--- 

## Introduction
[gRPC][grpc] is increasingly getting more popular and as a result, it is encountered more often during security assessments. In this blog post, I explain the different approaches to security test gRPC services depending on the type of assessment. [At the end][theend], I will show how to extend the [blackboxprotobuf][blackboxprotobuf] Burp extension to support gRPC-web.

## gRPC 101
gRPC is an open source high performance Remote Procedure Call (RPC) framework. It allows developers to write a service definition using Protocol Buffers. The following service definition is a simple example as demonstrated in the [gRPC documentation][grpc_doc_intro]:
```protobuf
// The greeter service definition.
service Greeter {
  // Sends a greeting
  rpc SayHello (HelloRequest) returns (HelloReply) {}
}

// The request message containing the user's name.
message HelloRequest {
  string name = 1;
}

// The response message containing the greetings
message HelloReply {
  string message = 1;
}
```

It is then possible to automatically generate client and server stubs in [a variety of languages][grpc_variety_languages]:

![grpc_overview_doc][grpc_overview_doc]

The data exchanged between services is serialized. The serialization depends on the developer's choice, however by default it is [protobuf][protobuf]. Protobuf is a binary data format. Using it is ideal for performance, but it can cause certain hurdles when trying to security assess systems using such protocols.


## Security assessments on systems using gRPC
As part of a security assessment, the auditor will try various ways to find security vulnerabilities in the target application. Usually an intercepting proxy software is used to monitor and modify traffic between the client and the server. Since the traffic for gRPC services might be binary due to the usage of protobuf, making sense out of the traffic or modifying it becomes a challenge. This is mainly due to the fact that the protobuf binary encoding strips most type and field information. Having the service definitions (protobuf files) at hand will allow for easy inspection and modification of traffic. However, in practice this is not always the case and depends on the nature of the assessment:


#### White box
During a white box security assessment, documentation and source code is shared with the auditor. This means that common tools can be used to interact with gRPC services. A good example is Postman, which since 2022, [supports gRPC][postman_grpc_support]. It is almost always advised to put an intercepting proxy such as [Burp Suite][burp_suite] in-between to keep a history of traffic. In addition, tools like Burp Suite allows for traffic modification and has a scala of offensive capabilities compared to Postman. A typical setup would look as follow:
![grpc_mitm_whitebox][grpc_mitm_whitebox]

#### Grey box
Sometimes companies are reluctant to share source code and prefer to have the security engagement performed with limited information. Often this means that user accounts are provided. Sometimes (minimal) documentation is provided as well. It is best to convince the client beforehand to provide at least the gRPC service definition files if a complete source code review is off the table. More often than not, clients are willing to share protobuf files for a better testing coverage. This means that the same setup can be used as the one used during a white box assessment. Otherwise, refer to the black box approach as described next.

#### Black box
Although not ideal, sometimes clients are not willing to share source code or service definition files. Attacking gRPC based services can get tricky in such cases, but not impossible. Here are a few ways:
- **Reflection / introspection:** occasionally, developers forget or knowingly leave [gRPC server reflection enabled][grpc_server_reflection] (protip: do some recon for tst/acc environments where reflection might be enabled). This allows clients that do not have the service definition files to query the server for RPC requests and responses, similar to [GraphQL introspection][graphql_introspection]. Postman [supports gRPC server reflection][postman_grpc_reflection_support], which enables testing in a similar fashion as described in the white-box approach.
![grpc_postman_reflection][grpc_postman_reflection]
- **Reversing / hooking:** If you got some reverse engineering experience, then reversing the generated RPC methods in the target client might also be an option. The RPC methods are often not obfuscated. A quick search for "grpc" in an Android app, might already reveal some interesting functions to hook:
![grpc_android_reversing][grpc_android_reversing]
Next, use an instrumentation framework like [Frida][frida] to hook the methods of interest and dynamically change values in memory. The [Brida Burp extension][brida] might help in this endeavor.
- **Blackbox Protobuf:** The NCC Group released the [Blackbox Protobuf repository][blackboxprotobuf]. It allows for working with protobuf messages without having access to the service definition file. It can be used as a Python library or installed as a Burp extension. You might wonder how is this possible without a Protobuf file? It basically tries to parse protobuf data and makes a best effort to guess the type. The field name cannot be recovered as it is lost during serialization. It is not ideal, but it is better than nothing as it can recover most/general structures. After following the exact [installation instructions for BBPB for Burp Suite][bbpb_installation], a new tab can be noticed on requests & responses that contain a protobuf message:
![bbpb_tab][bbpb_tab]
Sometimes, the wrong type is guessed. In one instance, it interpreted a double as an integer. I knew this from the context of the application as I was testing and expecting latitude and longitude coordinates. Luckily, BBPB allows to manually edit types:
![bbpb_type_fix][bbpb_type_fix]
Finally, some applications might use Protobuf but the BBPB Burp extension does not detect it. This is true for example when [gRPC-web][grpc_web] is used. Fortunately, BBPB is flexible and can be extended.

## Extending Black Box ProtoBuf to support gRPC-web
The BBPB extension can be extended by editing the [`user_funcs.py`][user_funcs.py] file which contains various functions.

The `detect_protobuf` function is used to help BBPB identify a request/response containing protobuf data. The BBPB protobuf tab appears in the request/response if this function returns `True`. The protobuf tab does not appear if it returns `False`. If `None` is returned, the standard BBPB detection routine is performed. In the case of gRPC-web, searching for a `content-type` header containing `application/grpc-web-text` suffices:
```python
def detect_protobuf(content, is_request, content_info, helpers):
    """Function used to display the protobuf tab, three return values are possible:
    - Return true if it's protobuf,
    - Return false if it's not protobuf,
    - Return None to fallback to the built-in header detection mechanism
    """
    for header in content_info.getHeaders():
        if 'content-type' in header.lower() and 'application/grpc-web-text' in header.lower():
            return True
    return None
```

Next is the `get_protobuf_data` function. BBPB retrieves by default the protobuf data from the body of the request/response. Data encoding is a bit different in the case of gRPC-web. The [comment on grpc/grpc-web#634][comment_634] gives a good explanation on how to do this:

> The payload is base64-encoded. So the first step is to base64-decode it. After that, you get a series of bytes that's arranged in the "grpc-web" wire format, which is spec'ed out here:
> - https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md#protocol-differences-vs-grpc-over-http2.
>
> So in general it goes "marker" "4 bytes denoting length" "X bytes of data / trailer", and repeat.

A simplified visual representation looks as follow:
![grpc_web_protocol][grpc_web_protocol]

Implementing the above logic is straightforward in Python:
```python
def get_protobuf_data(content, is_request, content_info, helpers, request=None, request_content_info=None):
    """Retrieve protobuf data:
    1. Check for content type header and if it's 'application/grpc-web'
    2. Base64 decode payload
    3. Parse data length from bytes position 1,2,3,4 (position 0 denotes the marker)
    4. Retrieve data from position 5 up to (position 5 + data length)
    """
    for header in content_info.getHeaders():
        if 'content-type' in header.lower() and 'application/grpc-web' in header.lower():
            data = base64.b64decode(content[content_info.getBodyOffset():].tostring())
            protobuf_data_len = struct.unpack('>I', data[1:5])[0]
            return data[5:protobuf_data_len+5]
```

Consequently when changing data in the BBPB protobuf tab, it needs to somehow know how to reconstruct the protobuf data back to the encoded form (in this case gRPC-web). The reverse process is therefore applied as follows:
```python
def set_protobuf_data(protobuf_data, content, is_request, content_info, helpers, request=None, request_content_info=None,):
    """Set protobuf data in case the request is edited:
    1. Check for content type header and if it's 'application/grpc-web'
    2. Calculate data length and encode it in bytes, prefix it with the marker
    3. Concatenate the marker + encoded data length and data
    4. Encode everything in base64
    """
    
    for header in content_info.getHeaders():
        if 'content-type' in header.lower() and 'application/grpc-web' in header.lower():
            protobuf_data_prefix = "\x00" + struct.pack('>I', len(protobuf_data))
            return helpers.buildHttpMessage(content_info.getHeaders(), base64.b64encode(protobuf_data_prefix + protobuf_data))
```

The complete script can be found in the following repository [bbpb-grpc-web][bbpb_grpc_web].





[theend]: #extending-black-box-protobuf-to-support-grpc-web
[grpc]: https://grpc.io/
[blackboxprotobuf]: https://github.com/nccgroup/blackboxprotobuf
[grpc_doc_intro]: https://grpc.io/docs/what-is-grpc/introduction/
[grpc_overview_doc]: /assets/files/security_assessing_grpc_and_grpcweb_services/grpc_overview_doc.svg
[protobuf]: https://protobuf.dev/programming-guides/encoding/
[postman_grpc_support]: https://blog.postman.com/postman-now-supports-grpc/
[burp_suite]: https://portswigger.net/burp
[grpc_mitm_whitebox]: /assets/files/security_assessing_grpc_and_grpcweb_services/grpc_mitm_whitebox.drawio.png
[grpc_server_reflection]: https://grpc.github.io/grpc/core/md_doc_server_reflection_tutorial.html
[grpc_variety_languages]: https://grpc.io/docs/languages/
[graphql_introspection]: https://graphql.org/learn/introspection/
[grpc_postman_reflection]: /assets/files/security_assessing_grpc_and_grpcweb_services/grpc_postman_reflection.jpg
[postman_grpc_reflection_support]: https://blog.postman.com/latest-advancements-to-postmans-grpc-support/
[bbpb_installation]: https://github.com/nccgroup/blackboxprotobuf/tree/master/burp#installation
[grpc_android_reversing]: /assets/files/security_assessing_grpc_and_grpcweb_services/grpc_android_reversing.jpg
[frida]: https://frida.re/
[brida]: https://github.com/federicodotta/Brida
[bbpb_tab]: /assets/files/security_assessing_grpc_and_grpcweb_services/bbpb_tab.jpg
[bbpb_type_fix]: /assets/files/security_assessing_grpc_and_grpcweb_services/bbpb_type_fix.jpg
[grpc_web]: https://github.com/grpc/grpc-web
[user_funcs.py]: https://github.com/nccgroup/blackboxprotobuf/blob/master/burp/blackboxprotobuf/burp/user_funcs.py
[comment_634]: https://github.com/grpc/grpc-web/issues/634#issuecomment-530472903
[bbpb_grpc_web]: https://github.com/Hamz-a/bbpb-grpc-web
[grpc_web_protocol]: /assets/files/security_assessing_grpc_and_grpcweb_services/grpc_web_protocol.png