# Challenge Details
* Challenge Name: Switcheroo
* CTF: [Elttam libctfso-corrupt-penguin](https://github.com/elttam/libctfso-corrupt-penguin/tree/master)
* Catagory: Linux Memory Corruption
* Difficulty: Hard

# Overview
I got asked to try and solve this challenge with the mention that it went unsolved at a few CTFs a couple of years ago. Ended up coming up with an attack plan within a few hours but it took a few days longer to get a working solution because ASLR sucks.

We're given [source code](https://github.com/elttam/libctfso-corrupt-penguin/blob/master/ansible/roles/switcheroo/files/challenge.c) for the target binary which is pretty short and doesn't seem to do too much. Binary is set as suid and compiled with a bunch of annoying settings for exploitation:
* Stack canaries
* ALSR
* PIE
* Non-exec stack
* Partial RELRO

# First look
Skimming through the source code we can see it does the following:
1. Creates a new shared memory region with shm_open. The permissions are set to 777 so anybody can interact with it.
2. It's mmap'd into the process as read | execute and a size of 1024 bytes.
3. After 10,000 microseconds the shared memory object is closed and unlinked.
4. It spins in an endless loop reading the first int of the shared memory and using the value to determine which branch of a switch statement to take, each of which prints a different message.

Initially it doesn't look like we can do much. There's no writes so no overwriting or overflowing. The shared memory is opened with the O_EXCL flag so we can't sub in our own memory. 

# Diving into assembly
It's always good to check out what the program is doing at the assembly level even though we have source. Sometimes compilers make some weird choices that we might be able to take advantage of.

```
.text:00000A09                 push    0
.text:00000A0B                 push    esi
.text:00000A0C                 push    1
.text:00000A0E                 push    5
.text:00000A10                 push    400h
.text:00000A15                 push    0
.text:00000A17                 call    _mmap
.text:00000A1C                 mov     edi, eax
```
The pointer to the shared memory, which is used by the switch statement, is stored in EDI which is never written to again. The switch statement is clearly visible in IDA (Binary Ninja failed to work out the branches even though it knew what the jump table was). 

![image](https://user-images.githubusercontent.com/9779696/230784633-6a3f3653-2d60-4000-9b05-9f2e7c7c3a1b.png)

`[EDI]` is read and compared to 4 using an unsigned check. This corresponds to the default case. Given that it's an unsigned check, we can't use any cheeky negative values to try and break the jump table. 
However, if we look at the non-default branch we can spot a subtle thing we can take advantage of: The value of `[EDI]` is read again for use in the jump table. 
For some reason the compiler decided not to cache the value in a register and instead performs two reads: once for the default branch case, and again for the jump table calculation. This is a classic Time of Check Time of Use (TOCTOU) bug. 
If we can some how change the value in between the two reads, we can bypass the check against 4 and replace it with any value we like. 

Our bug is found, now to work out how to exploit it.

# Coming up with an attack plan
First of all we need to work out how the jump table works and what the value we control is used for.

```
.text:00000A7B                 mov     eax, [edi]
.text:00000A7D                 mov     edx, ebx
.text:00000A7F                 add     edx, ds:(jpt_A86 - 1FA0h)[ebx+eax*4]
.text:00000A86                 jmp     edx             ; switch jump
```
```
00000c94  uint32_t jump_table_c94[0x5] = 
00000c94  {
00000c94      [0x0] =  0xffffeae8
00000c98      [0x1] =  0xffffeafc
00000c9c      [0x2] =  0xffffeb10
00000ca0      [0x3] =  0xffffeb24
00000ca4      [0x4] =  0xffffeb42
00000ca8  }
```
`EDX` is first loaded with some value from `EBX`. `EBX` is then used again along with `EAX` (which we control) which ends up with an address within the jump table. The jump table then contains values that are added to `EDX`. 
These values are negative so it's actually a subtraction but that doesn't matter too much. What does matter, however, is that we don't have full control over the jump target used by `JMP EDX` by only controlling `EAX`. 
To perform an arbitrary jump we would need to control not only the address read from, but also the value read. Luckily we have a big 1024 byte buffer we can freely write into, if we can index into it.

The instruction we need to abuse is a bit easier to read in Binja and GDB: `add edx, dword [ebx+eax*4-0x130c]`. Playing with the binary in GDB shows that `EBX` contains the address of the GOT table and is constant relative to the start of the program at `0x1fa0`.

The path forward from here isn't too hard to work out:
1. We perform a race between some valid value and some unknown value `x` that we need to calculate.
2. This value `x` is chosen such that `Base Address + 0x1fa0 - 0x130c + x * 4` results in an address we can control, ideally within the shared memory region.
3. Another value `y` is stored at the address read above such that `Base Address + 0x1fa0 + y` results in an address within the shared memory.
4. Put some shellcode in the buffer at that address and profit.

Our final buffer layout looks like:
```
[ EAX / X | Y | Shellcode ... ]
```
Where:
* `X = (Shared Memory - Base Address - 0x1fa0 + 0x130c + 4) / 4`
* `Y = Shared Memory - Base Address - 0x1fa0 + 8`

The additions of `4` and `8` above are just to index into the buffer itself. In both cases the subtraction of `0x1fa0` is to account for the value in `EBX`. 

For the shellcode I used [this](https://masterccc.github.io/tools/shellcode_gen/) site with a slight modification to set `EDX` properly.

# ASLR
If that was all that was required then we'd be pretty much done. There's just one big blocker to this plan: ASLR. Both the addresses of the executable base and the mmap'd memory region are randomised and we need to know both of them to calculate the correct values for `x` and `y`.
In most CTF challenges (and real exploitation) you'd first leak the address of some known object, from which you could calculate the address of libc or the binary. We would still need to find the mmap region, but it's one less thing to worry about.

However, in this case, we have no leak. No way to know where in memory either the jump table or the shared memory is.

This was a major blocking point. Messing around with printing the address of the mmap region in my exploit suggested that there was only 8 bits of randomness for the region, giving 256 different possibilities of where it could be. Assuming that the executable base
used the same amount of bits, that gives 16 bits we need to guess or a 1 / 65535 chance of correctly guessing both values. If we guess wrong we crash and need to try again with a different set of numbers. 1 / 65535 is definitely within the realm of bruteforcing, but it wouldn't be fun.

What to do? Rather than trying to bruteforce with a ton of solvers in parallel (which didn't work to well on my machine), I decided to just run the program a ton of times and log all the addresses used. 
This way I could confirm that only 8 bits for each of the addresses were random, and could maybe see if the distribution was uniform. Maybe there was something that could increase the odds of picking a winning set of numbers.

![image](https://user-images.githubusercontent.com/9779696/230786998-6d4aa36d-2552-4d93-bb41-aead92a375e8.png)
![image](https://user-images.githubusercontent.com/9779696/230787077-36094f8a-36bd-4f94-b2e4-6183b6e0c8aa.png)
![image](https://user-images.githubusercontent.com/9779696/230787147-be031d2f-e213-4e60-9785-a86b669d2185.png)

The distribution of each memory region is indeed pretty uniform. However, if we look at the deltas of the the address pairs (mmap region address - base address) we can see that it's not uniform. 
The center of the range occured roughtly 250 / 60000 times which is pretty close to 1 / 256. This gets us down to the same probability as only needing to guess one of the pair.

In retrospect this was entirely unnecessary and basic probability theory would have been enough to realise these results. But hey, cool graphs. 

# Finishing up
From here I just picked a number randomly from the middle of the range: `0xa1980000`. It was a nice round number towards the middle so I picked it. 
This needs to sub in for the `Shared Memory - Base Address` value in the calculations above giving:
* `X = (0xa1980000 - 0x1fa0 + 0x130c + 4) / 4 = 0x2865fcdc`
* `Y = 0xa1980000 - 0x1fa0 + 8 = 0xa197e068`

Our exploit program needs to open the shared memory within 10,000 microseconds, set up the buffer with the correct values and shellcode, and then repeatedly switch the first value between `0x2865fcdc` and zero. If our guess was wrong, simply run the exploit again until we get it.

Eventually, depending on how lucky you get, the flag pops out. 

![image](https://user-images.githubusercontent.com/9779696/230787991-20d85ce5-0fcc-4cce-b2b2-6976d7815e9c.png)


