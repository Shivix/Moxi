# MOdular eXtensIble debugger (WIP)
A modern debugger designed with modularity and extensibility in mind.

Current support:
* Linux
* x86-64
* Zig binaries
* C Binaries
* PIE/ non-PIE

Planned support:
* Dynamically linked libraries
* BSD support
* ARM support
* Likely more

Up for consideration:
* Debugging multiple executables at once
* C++ executables
* Mac support

## Usage
`moxid` is the long-lived debugger daemon. This is what attaches to the child process.
The short-lived command programs connect to it over localhost port 44500 to trigger desired behaviour.

NOTE: eventually there will be an init binary that when ran in the shell sets up a wrapper command for nicer usage (moxi start vs moxi-start etc.).

Running `moxi-start` again replaces the current debuggee while keeping `moxid` running.

## Customizing your experience
I encourage you to experiment and build the experience that suits you, but if you're looking for
some inspiration, here are some examples I use:

* A Fish shell function for printing the current file, highlighting the current line being run
```fish
function source
    set source (moxi-source)
    set source (string split ":" $source)
    bat $source[1] --highlight-line $source[2]
end
```

## Installation

## Testing
Example test binaries can be built with `zig build testbinaries`. These are the executables used within our test scripts.
A test script is provided to run through each of these binaries doing a range of actions.

## Issues
Any bugs/ requests can be added to the [issues](https://github.com/Shivix/Moxi/issues) page on the github repository.
