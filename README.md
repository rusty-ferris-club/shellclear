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
<br/>
<b>:triangular_flag_on_post: Show sensitive command summary when open a new terminal</b>
<br/>
<b>:eyes: Clear sensitive commands from shell history</b>
<br/>
<b>:see_no_evil: Stash your history command before presentations OR screen sharing</b>
<br/>
<hr/>
</p>

# Shellclear
The idea behind `shellclear` is to provide a simple and fast way to secure you shell commands history
## Installation
```bash
brew tap rusty-ferris-club/tap && brew install shellclear
```
Or download the binary file from [releases](https://github.com/rusty-ferris-club/shellclear/releases) page.

## Add Summary 
Add in shell profile (~/.zshrc / .bash_profile / .bashrc)
```
eval $(shellclear --init-shell)
```
![motd](./media/motd.png)


## Using
```
$ shellclear --help

Secure shell commands

USAGE:
    shellclear [OPTIONS] [SUBCOMMAND]

OPTIONS:
    -h, --help           Print help information
        --init-shell     Show sensitive findings summary for MOTD
        --log <LEVEL>    Set logging level [default: INFO] [possible values: OFF, TRACE, DEBUG,
                         INFO, WARN, ERROR]
        --no-banner      Don't show the banner
    -V, --version        Print version information

SUBCOMMANDS:
    config     Create custom configuration
    find       Find sensitive commands
    help       Print this message or the help of the given subcommand(s)
    restore    Restore backup history file
    stash      Stash history file
```

## Supported Shells
- bash
- zshrc
- fish

## :eyes: Find Sensitive Commands
Sensetive data can be stored in your history file when export a token of something or running a script with token. 
```sh
$ shellclear find
```
![find](./media/find.png)




### :broom: Clear findings :
```sh
$ shellclear clear
```

## :luggage: Backup shell history before clear
```sh
$ shellclear clear --backup
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

## :pencil2: Custom Sensitive Patterns
To create a custom sensitive patters you can run
```sh
$ shellclear config
```
Config command will create a file that you can add your custom patters that `shellclear` automatically.

### Validate Config File
Validate syntax file
```sh
$ shellclear config --validate
```

## :luggage: Restore shell history
```sh
$ shellclear restore
```

# Thanks
To all [Contributors](https://github.com/rusty-ferris-club/shellclear/graphs/contributors) - you make this happen, thanks!

# Copyright
Copyright (c) 2022 [@kaplanelad](https://github.com/kaplanelad). See [LICENSE](LICENSE.txt) for further details.
