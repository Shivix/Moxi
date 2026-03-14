# MOdular eXtensIble debugger (WIP)
A modern debugger designed with modularity and extensibility in mind.

As of right now, I am purely focusing on debugging a single Zig binary not linked to libc, on linux.
As I progress I will add support for:
* Zig binaries linked to libc
* Zig binaries linked to other libraries
* Statically linked c binaries
* Dynamically linked c binaries
* Multiple binaries at once
* C++ binaries
* Mac support
* BSD support
* And maybe more

## Usage
Moxid is the main application that will attach to any process you wish to debug. This should be
started using systemd, until you're actively debugging, it will not be doing anything.

Use `moxi --help` or `man moxi` for more details.

## Customizing your experience
I encourage you to experiment and build the experience that suits you, but if you're looking for
some inspiration, here are some examples I use:

* A Fish shell function for printing the current file, highlighting the current line being run
```fish
function source
    set source (moxi source)
    set source (string split ":" $source)
    bat $source[1] --highlight-line $source[2]
end
```

## Installation

## Testing
Example test binaries can be built with `zig build testbinaries`. These are the binaries used within our test scripts.

## Issues
Any bugs/ requests can be added to the [issues](https://github.com/Shivix/Moxi/issues) page on the github repository.
