# Security Middleware Project

This git contains source code for the Security Middleware library.

All project information can be found at
[Security Middleware Confluence](https://confluence.sw.nxp.com/display/EPSTEC/Security+Middleware)


----

## Table Of Content

1. [Pre-commit hook](#pre-commit-hook)
   1. [Enabling pre-commit hooks](#enabling-pre-commit-hooks)
   2. [Bypassing pre-commit hooks](#bypassing-pre-commit-hooks)
2. [Formating Tools](#formating-tools)
   1. [Installing clang-format](#installing-clang-format)
   2. [Installing checkpatch](#installing-checkpatch)
3. [List of changes](#list-of-changes)

----

## Pre-commit hook
Some pre-commit hooks are available to check:
* The commit message format
* The coding syle using clang-format
* Run linux checkpatch
* Check file copyright in commit

### Enabling pre-commit hooks
This is under the developer responsability to enable the pre-commit hook on
his local environment. The below script has to be executed one time in the
source tee.

```
$ cd <your-source-tree>
$ ./scripts/enable-git-hooks.sh
```

The script create linked in the .git folder:
* git-hooks/commit-msg: check the commit message.
* git-hooks/pre-commit: run all scripts present in git-hooks/pre-commit.d/
* git-hooks/pre-commit.d/check-copyright: verify that all source files
    copyright header. To remove files from the check, update the file
    `.check-style.ignore` in the root directory.
* git-hooks/pre-commit.d/clang-format: run clang-format on all source files.
    Coding format is defined in the file `.clang-format` in the root directory.
* git-hooks/pre-commit.d/checkpatch: run checkpatch on all files.

### Bypassing pre-commit hooks
If for whatever reason you need to disable the hooks, simply add the
--no-verify option to git commit command.
It's no recommended to bypass hooks if commit is to be merge in mainline.

___

## Formating Tools

### Installing clang-format
The minimum version required is the version 9.0.
To install the latest version in Ubuntu run the command:

```
sudo apt install clang-format
```

### Installing checkpatch
There is no manual installation to be done. Script is uploading checkpatch in
the top level .tmp directory created if not existing.
The file .checkpatch.ignore excludes files/directory from the checkpatch
verification.

**Note:** the scripts/checkpatch.sh can be executed as a normal script without
using the pre-commit hook.
More help with `./scripts/checkpatch.sh --help`

___

## List of changes
The list of changes can be found in the [ChangeLog](./CHANGELOG.md) file.

