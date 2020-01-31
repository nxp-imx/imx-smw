# Security Middleware Project

This git contains source code for the Security Middleware library.

All project information can be found at
https://confluence.sw.nxp.com/display/MICRAT/Security+Middleware

## Pre-commit hook
Some pre-commit hooks are availabe to check:
- The commit message format
- The coding syle using clang-format version 9.0

### Enabling pre-commit hooks
This is under the developer responsability to enable the pre-commit hook on
his local environment. The below script has to be executed one time in the
source tee.
$ cd <your-source-tree>
$ ./scripts/enable-git-hooks.sh

The script create linked in the .git folder:
- git-hooks/commit-msg: check the commit message.
- git-hooks/pre-commit: run all scripts present in git-hooks/pre-commit.d/
- git-hooks/pre-commit.d/check-copyright: verify that all source files
    copyright header. To remove files from the check, update the file
    `.check-style.ignore` in the root directory.
- git-hooks/pre-commit.d/clang-format: run clang-format on all source files.
    Coding format is defined in the file `.clang-format` in the root directory.

### Bypassing pre-commit hooks
If for whatever reason you need to disable the hooks, simply add the
--no-verify option to git commit command.
It's no recommanded to bypass hooks if commit is to be merge in mainline.

### Installing clang-format
The version required is the version 9.0. Installation can with the command
`sudo apt install clang-format-9`
