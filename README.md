# Shellclear
The idea behind `shellclear` is to provide a simple and fast way to manage your local shell history file
## Use Cases
1. Clear sensitive commands from shell history.
2. Stash your history command before presentations OR screen sharing.
3. Create a profile history file for specific use cases.


## Installation
```bash
brew tap kaplanelad/tap && brew install shellclear
```
### Using Homebrew:

Or download the binary file from [releases](https://github.com/rusty-ferris-club/shellclear/releases) page.


## How it work

## :eyes: Find And Clear Sensitive History Commands
Sensetive data can be stored in your history file when export a token of something or running a script with token. for example:
```sh
...
export GITHUB_TOKEN=...
export AWS_ACCESS_KEY=...
./myscript.sh ghp_XXX...
```

In this case `shellcler` detect those commands:
```sh
hshellclear find # --clear --backup
```


## :zap: Stash/Pop 
You can stash your history shell by running the command:
```sh
shellclear stash
```
now your history shell is clear, to bring back your history run the command:
```sh
shellclear pop
```

## Supported Shells
- bash
- zshrc
- fish
