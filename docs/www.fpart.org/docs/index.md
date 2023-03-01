
![Fpart](img/Fpart.png)

# About

Fpart is a **F**ilesystem **part**itioner. It helps you sort file trees and
pack them into bags (called "partitions"). It is developed in C and available
under the BSD license.

# Key features

## Fpart

* Blazing fast crawling!
* Generates partitions on a number/file number/size basis
* Provides a live mode with hooks to act immediately on generated file lists
* Supports generating partitions from arbitrary input (e.g. du's output)

## Fpsync

* Parallelizes rsync(1), cpio(1) or tar(1) jobs
* Supports using a SSH cluster for efficient data migrations
* Starts transfers while FS crawling still goes on
* Supports remote target URLs when using rsync(1)
* Parallelizes your final rsync(1) pass too!
* Provides transfer runs' status/resume/replay
* Nearly no dependencies (mostly shell and common tools)

# Compatibility

Fpart is primarily developed on FreeBSD.

It has been successfully tested on :

* FreeBSD (i386, amd64)
* GNU/Linux (x86_64, arm)
* Solaris 9, 10 (Sparc, i386)
* OpenIndiana (i386)
* NetBSD (amd64, alpha)
* Mac OS X 10.6, 10.8, 11.2 (x86_64, arm64)

and passed Coverity Scan tests with success.

[![Coverity Scan Build Status](https://scan.coverity.com/projects/27316/badge.svg)](https://scan.coverity.com/projects/fpart)

# Installing from a package

Packages are already available for many operating systems :

* [FreeBSD](https://www.freshports.org/sysutils/fpart)
* [Debian](https://packages.debian.org/fpart)
* [Ubuntu](https://packages.ubuntu.com/search?keywords=fpart)
* [CentOS/Fedora](https://src.fedoraproject.org/rpms/fpart)
* [NixOS](https://search.nixos.org/packages?query=fpart)
* [MacOS (Homebrew)](https://formulae.brew.sh/formula/fpart)

so you can use your favourite package manager to get ready.

# Installing from source

If a pre-compiled package is not available for your favourite operating system,
installing from sources is simple. First, get the source files :

    $ git clone "https://github.com/martymac/fpart.git"
    $ cd fpart

Then, if there is no 'configure' script in
the main directory, run :

    $ autoreconf -i

(autoreconf comes from the GNU autotools), then run :

    $ ./configure
    $ make

to configure and build fpart.

Finally, install fpart (as root) :

    # make install

# Author / Licence

Fpart has been written by [Ganael LAPLANCHE](mailto:ganael.laplanche@martymac.org)
and is available under the BSD license (see COPYING for details).

Source code is hosted on :

* [Martymac.org](http://contribs.martymac.org)
* [Github](https://github.com/martymac/fpart)
* [Sourceforge](http://www.sourceforge.net/projects/fpart)

Documentation is available on :

* [Fpart.org](http://www.fpart.org)

Thanks to Jean-Baptiste Denis for having given me the idea of this program !

# Donation

If fpart (or fpsync) is useful to you or your organization, you can make a donation here:

[![paypal](https://www.paypalobjects.com/en_US/FR/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=HSL25ZED2PS62&source=url)

That will help me not running out of tea :)

# Contributions

FTS code originally comes from FreeBSD :

    lib/libc/gen/fts.c -> src/fts.c
    include/fts.h      -> src/fts.h

It has been slightly modified for portability and is available under the BSD
license.

Also, big thanks to my beloved wife and daughters for their invaluable support
and more particularly for the discussion we had about Fpart logo :)
