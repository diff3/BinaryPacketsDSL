# Install

```bash
npm install -g @vscode/vsce
vsce package
code --install-extension bpdlang-syntax-0.0.1.vsix

npm version patch   # 0.0.1 -> 0.0.2
npm version minor   # 0.1.0
npm version major   # 1.0.0

# optional
code --uninstall-extension dittnamn.bpdlang-syntax
```



## code in path

```bash

Macos:
   1. Öppna VSCode.
   2. Tryck Cmd+Shift+P för att öppna Command Palette.
   3. Skriv: Shell Command: Install 'code' command in PATH

Linux flatpack:
   1. Add: alias code='flatpak run com.visualstudio.code' to .bashrc
   2. source .bashrc
```
