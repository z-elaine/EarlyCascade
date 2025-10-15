<h1 align="center">EarlyCascade</h1>


<p align="center">
  <img src="preview.png" alt="Logo">
</p>

> It's a modern and stealthy process injection technique was discovered by [Outflank](https://www.outflank.nl/) that involves injecting and executing code in the early stages of process creation before loading EDRs for their user mode detection measures. EarlyCascade technique forces enabling the Shim engine, allowing to hijack a Shim engine callback.

## About the proof-of-concept
1. Creating a process in suspended mode.
2. Dynamically locating the addresses of enabling flag and callback.
3. Remotely allocating memory for our stub and shellcode.
4. Injecting the stub and shellcode into the target process.
5. Force the shim engine to be enabled.
6. Hijacking a shim engine callback.
7. Triggering the callback by resuming the process thread.

At this point, the stub gets executed, and does the following:
1. Disrupting the initialization of detection measures.
2. Disabling the Shim engine to avoid crash.
3. Queuing an Asynchronous Procedure Call (APC) that executes the shellcode later.

## References
- [Introducing Early Cascade Injection: From Windows Process Creation to Stealthy Injection](https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/)

## Blog
Recently the research team at Outflank published a very interesting paper. From the start, their stated goal was to find a technique that allows performing process injection very early — during the initial creation stages of a process — before Endpoint Detection and Response tools (EDRs) have time to initialize their detection measures. That way the malicious code can take preemptive actions against the EDR and disable it before it even starts.

Before we talk about how the technique works, we need to understand how EDRs actually monitor processes. EDRs implement a driver that runs in kernel-land; the driver registers notification callbacks with the system. As soon as an event occurs — for example the creation of a new process or thread — the kernel invokes the EDR’s callback so the EDR learns about the event and reacts. For example, on process creation the EDR may immediately inject its security measures into the process before the process’s entrypoint is called, start monitoring it and observe its behavior.

The research focused on the Windows loader architecture and how it operates. The challenge is that even if you find a code-execution technique at that early stage, the code will be extremely limited and cannot use normal system services: during the early stages of process creation the loader is “acquired” (locked), which means you cannot load DLLs, and many basic things haven’t finished loading yet. Therefore any code running at that time cannot, for example, create new threads or make TCP/HTTP connections to a C2. And if you wait for the OS to release the loader, the EDR may already have taken control of the process — so you end up achieving nothing.

The researchers discovered an undocumented callback related to a technology called the Shim Engine — Microsoft’s compatibility-handling component — and that engine runs very early during process creation (which is exactly what we want). Unfortunately the Shim Engine is disabled by default.

They found a bypass — a way to enable the Shim Engine so that the callback will be invoked early. But they ran into a problem: enabling the Shim Engine causes many other callbacks to be invoked, not just the one they need, and that can crash the process.

So they reasoned that to leverage the callback properly they first need to inject a small bootstrap — call it a stub — and hijack the callback so it executes that stub. The stub must then disable the Shim Engine to avoid the crashing problem. And as we said, we can’t execute arbitrary shellcode at that point because of the loader lock, so the stub defers execution of the shellcode until the loader is unlocked. They stopped the paper at that point and left the rest to the reader’s imagination — they didn’t publish a PoC or an implementation.

Of course the technique is powerful and effective and has some nice subtleties, so I decided to build my own PoC. But there were some thorny challenges.

First, the bootstrap/stub that is injected into the process and executes there must be raw machine code that the CPU can execute directly. There were two options: write it in C/C++ and perform injection into the same process (i.e., the parent duplicates itself and injects into the child, then the child redirects execution flow to run the bootstrap — similar in spirit to fork on Linux). But higher-level code is extremely limited at that stage and a small mistake can crash the target, and I wanted the ability to inject into any process not just a self-injecting scenario. So the better alternative was to implement the stub in assembly: that gives super control over the machine and lets us avoid anything that might cause a crash.

The stub first performs clobbering of EDRs — it eats them up before they get a chance to act — and, as mentioned, disables the Shim Engine to prevent the crash. It then queues an Asynchronous Procedure Call (APC) whose role is to run the shellcode; the dispatcher will invoke the APC automatically later even before the process entrypoint is called.

The second problem for me was: where do we find the callback and the flags we need to hijack?

This requires reverse engineering the Shim Engine. Initially I used static offsets, but system changes make that approach break across versions. I tried to find a special pattern in the targets’ addresses or at least nearby, but I couldn’t find anything reliable. I tried to see if the loader sets any runtime-accessible value near those addresses before the callbacks execute, so we could compute the exact memory location, but again I found nothing dependable.

After some walks and thinking over several cups of tea I came up with the idea: why don’t we do what the CPU itself does and reach the needed memory addresses in the same way? (I hadn’t written code yet — just doing reverse engineering and thinking.) What I found is shown in the image below.

Machine instructions in memory contain memory offsets that are RIP-relative, so with a simple calculation you can determine the required addresses in memory. That was the solution I used: scan the executable section of the Shim Engine and extract those offsets.
