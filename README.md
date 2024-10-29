# ps5-payload-elfldr
This is an ELF loader for PS5 systems that have been jailbroken using either the
[BD-J ps5-payload-loader][bdj], or the [webkit approached from Specter][webkit].
Unlike the ELF loaders bundled with those exploits, this one uses the ptrace
syscall to bootstrap itself into the `SceRedisServer` process, and then launches
itself into a new process that keeps running in the background, even when
playing games. Furthermore, this ELF loader will also resume its execution when
the PS5 returns from rest mode. Since payloads are executed in induvidual
processes, this ELF loader keeps on running even if a payload crashes.

## Quick-start
To deploy ps5-payload-elfldr, first launch a kernel exploit that provides
a rudimentary ELF loader on port 9020, e.g., [BD-J ps5-payload-loader][bdj],
or the [webkit approached from Specter][webkit]. Then, run the following:
```console
john@localhost:~$ export PS5_HOST=ps5
john@localhost:~$ wget -q -O - https://github.com/ps5-payload-dev/elfldr/releases/download/v0.16/Payload.zip | gunzip -c -d | nc -q0 $PS5_HOST 9020
```
**Note**: recent versions of the [BD-J ps5-payload-loader][bdj] includes a
binary version of ps5-payload-elfldr which can be launched directly from the
menu system.

## Building
Assuming you have the [ps5-payload-sdk][sdk] installed on a Debian-flavored
operating system, ps5-payload-elfldr can be compiled using the following
set of commands:

```console
john@localhost:ps5-payload-elfldr$ sudo apt-get install xxd
john@localhost:ps5-payload-elfldr$ export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
john@localhost:ps5-payload-elfldr$ make
```

## Reporting Bugs
If you encounter problems with ps5-payload-elfldr, please [file a github issue][issues].
If you plan on sending pull requests which affect more than a few lines of code,
please file an issue before you start to work on you changes. This will allow us
to discuss the solution properly before you commit time and effort.

## License
ps5-payload-elfldr is licensed under the GPLv3+.

[bdj]: https://github.com/john-tornblom/bdj-sdk/tree/master/samples/ps5-payload-loader
[sdk]: https://github.com/ps5-payload-dev/sdk
[webkit]: https://github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit
[issues]: https://github.com/ps5-payload-dev/elfldr/issues/new
