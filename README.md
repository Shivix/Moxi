# MOdular eXtensIble debugger (WIP)
A modern debugger designed with modularity and extensibility in mind.

This is still in the early stages, some details here may not be accurate.
I have not had much time to work on this, but it is not abandoned, this is a long term project.
Please feel free to give feedback at any stage by creating an issue.
It is a unique idea which I believe has alot of potential.

## Usage
Moxid is the main application that will attach to any process you wish to debug. This should be
started using systemd.

Run `moxi init` as part of your shell config to configure the tools for communicating with the
daemon.

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
Can be installed using:
```
cargo install moxi
```

## Issues
Any bugs/ requests can be added to the [issues](https://github.com/Shivix/moxi/issues) page on the github repository.
