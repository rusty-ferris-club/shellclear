[![Release](https://github.com/rusty-ferris-club/shellclear/actions/workflows/release.yml/badge.svg?branch=main)](https://github.com/rusty-ferris-club/shellclear/actions/workflows/release.yml)
[![Build](https://github.com/rusty-ferris-club/shellclear/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/rusty-ferris-club/shellclear/actions/workflows/build.yml)

<p align="center">
<br/>
<br/>
<br/>
   <img src="media/shellclear.svg" width="300"/>
<br/>
<br/>
</p>
<p align="center">
<b>:eyes: Clear sensitive commands from shell history</b>
<br/>
<b>:see_no_evil: Stash your history command before presentations OR screen sharing</b>
<br/>
<b>:triangular_flag_on_post: Create a profile history file for specific use cases.</b>
<br/>
<hr/>
</p>

# Shellclear
The idea behind `shellclear` is to provide a simple and fast way to secure you shell commands history
## Installation
```bash
brew tap rusty-ferris-club/tapp && brew install shellclear
```
Or download the binary file from [releases](https://github.com/rusty-ferris-club/shellclear/releases) page.

## Using
```
$ shellclear --help
shellclear 0.1.1
Secure shell commands

USAGE:
    shellclear [OPTIONS] [SUBCOMMAND]

OPTIONS:
    -h, --help           Print help information
        --log <LEVEL>    Set logging level [default: INFO] [possible values: OFF, TRACE, DEBUG,
                         INFO, WARN, ERROR]
        --no-banner      Don't show the banner
    -V, --version        Print version information

SUBCOMMANDS:
    find       Find sensitive commands
    help       Print this message or the help of the given subcommand(s)
    restore    Restore backup history file
    stash      Stash history file
```

## Supported Shells
- bash
- zshrc
- fish

## :eyes: Find And Clear Sensitive History Commands
Sensetive data can be stored in your history file when export a token of something or running a script with token. for example:
```sh
export GITHUB_TOKEN=<TOKEN>
export AWS_ACCESS_KEY=<KEY>
./myscript.sh ghp_<>
```

### Run `shellcler find` command:
```sh
$ shellclear find
```

### :broom Clear findings command run:
```sh
$ shellclear find --clear
```

## :luggage: Backup shell history before clear
```sh
$ shellclear stash --clear --backup
```

## :see_no_evil: Stash/Pop 
You can stash your history shell by running the command:
```sh
$ shellclear stash
```
now your history shell is clear, to bring back your history run the command:
```sh
$ shellclear pop
```


## :see_no_evil: Stash/Pop 
You can stash your history shell by running the command:
```sh
$ shellclear stash
```
now your history shell is clear, to bring back your history run the command:
```sh
$ shellclear pop
```

## :luggage: Restore shell history
```sh
$ shellclear backup
```

# Thanks
To all [Contributors](https://github.com/rusty-ferris-club/shellclear/graphs/contributors) - you make this happen, thanks!

# Copyright
Copyright (c) 2021 [@kaplanelad](https://github.com/kaplanelad). See [LICENSE](LICENSE.txt) for further details.
