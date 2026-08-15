# breaking ijiami

this is how i got the real dex out of an app packed with ijiami, including the 4th
gen vmp build. i am writing down the process, not any one target.

## what ijiami does

the real classes.dex is encrypted on disk. a native stub decrypts it into memory
at runtime. on the strong builds the code loads as compactdex, the header gets
wiped or faked so a plain dump looks like garbage, and a vmp layer turns method
bodies into its own bytecode. on top of that it watches for frida, ptrace,
emulators and sandboxes and bails or crashes if it sees one.

## what did not work

frida got killed or the app respawned clean. blackdex was the right idea since it
dumps from memory after the packer decrypts, but it runs the target inside a
virtual app, so ijiami's sandbox checks block it, and on an emulator the virtual
app engine will not even run the target. static tools only see the stub because
the real code is encrypted on disk. every one of these lives inside the sandbox
ijiami controls, so it can see them.

## the idea that worked

built darkdex and ran the app under redroid, which is real android in a container,
not an emulator, so it gets past the emulator checks. the part that matters is that
a container process is just a normal linux process on the host. so from the host i
can read /proc/<pid>/mem directly. that is outside the android sandbox. no frida,
no ptrace, nothing for ijiami to notice. it cannot defend against a reader it
cannot see.

so i let the app run until the classes load and the packer has pushed everything
into ram, then i read the memory from the host and carve the dex out.

## carving and recovery

first pass scans every readable region for a dex or cdex header and pulls out
whatever validates. that gets the framework and any clean dex.

the app's own dex is the hard part because ijiami wrecks the header. so the second
pass ignores the header and anchors on the map_list, the section index that android
itself has to keep intact to run the code. from the map_list i rebuild a valid
header and carve the dex. this is the part most dumpers miss.

a third pass mines the raw memory for the backend urls, the class map and the
packer fingerprint, which still helps even when the dex cannot be cleanly rebuilt.

## compactdex

when the code loads as compactdex the code items use a compact pre header and a
shared data section, so it will not decompile as standard dex. converting it means
expanding each compact code item back into the standard layout and splicing the
shared data back in. the vmp methods stay vmp, that is by design, but everything
around them comes back.

## root vs no root

on redroid the host already sees the memory, so the read needs nothing special. on
a real phone the same idea works from inside an app with root, it reads the target
/proc/<pid>/mem after launching it.

without root you cannot read another process memory at all, that is a kernel rule.
so the no root path just pulls the on disk dex from the apk. for an unpacked app
that is the real code. for a packed app it is only the stub, since the decrypted
code lives in ram and needs root to reach.

## putting it together

darkdex.sh runs on the redroid host and does the carve, the recovery and the intel
in one shot. darkdex.apk does the same on the device, root mode for the full memory
dump and no root mode for the on disk dex. both work on ijiami and on other packers,
because none of this cares which packer is used. anything that decrypts code into
memory to run it can be read once it is in memory.

## v2: catch it at the open, not after

the snapshot approach is a race against the packer's cleanup. ijiami hands the
runtime a valid dex, lets it map, then wipes the header (and can chew up the
map_list) so a later scan finds garbage. but the runtime has to be handed a
structurally valid dex to run it. so there is always one instant, inside
`DexFileLoader::OpenCommon(base, size)`, where the fully decrypted, valid dex is
sitting in memory.

so in v2 i stopped scanning after the fact and put kernel probes on that function
from the host. every dex the app opens fires the probe with its base and size, and
i read it out of `/proc/<pid>/mem` right then, before any wipe. same thing for
`ClassLinker::DefineClass`, which fires per class with the class name. that gives a
live list of every class and catches the code the packer only decrypts right before
it runs. the probes live in the kernel, so the anti debug never sees them, and they
fire on every event, so they keep going through the respawns ijiami does under its
anti tamper. on the app that pushed me to build this (call it `com.example.player`)
it pulled a cleaner, larger app dex than any snapshot, around 9,600 classes, and it
disassembles clean.

when even that is not enough, header and map_list both wiped in memory, the runtime
still keeps a live `DexFile` object on the heap that holds the true start and size.
`darkdex_artwalk` reads the dex straight from those object bounds.
