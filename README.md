# StackBombing
A highly sophisticated technique which allows code injection onto a chosen running process, while bypassing every security mechanism (checked until Windows 10 build 1909).

Stackbombing abuses the Alertable state mechanism in Windows machines. While the target thread is in this state, Stackbombing writes to this thread's current stack its payload, after it saved the normal thread state.

When the thread returns from the Alertable-state, the `retn` instruction jumps to the malicious ROP chain inserted by Stackbombing.
After Stackbombing finishes running the ROP chain, a clean up for the malicious stack occurs, and the thread stack is being rerwitten.

With this technieque, an attacker is able to be stealty, and pwn every process he disires.
