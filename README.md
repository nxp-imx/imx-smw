# Security Middleware Project

This git contains source code (C standard) for the NXP Security Middleware library.

The NXP Security Middleware Library is a software library exposing a set of
unify APIs to execute operations on i.MX Secure Subsystems. The library
intends to be a "bridge" or "wrapper" formatting operation's parameters
function of the Secure Subsystem used.

The objectives of this library are:
- Exposing the same set of APIs regardless the secure operation.
- Making target Secure Subsystems configurable by using a configuration file. This configuration is text buffer loaded at runtime and describing operations versus Secure Subsystems.
- Offering the possibility to use a Secure Subsystem transparently by defining a "default" Secure Subsystem per operation in the configuration file.
- Allowing to use a particular (not default one) Secure Subsystem for each operation.
- Being OS' agnostic. The final target library include a specific OS Abstraction Layer to access non-standard C library system resources.
- Supporting multiple applications and threads.

## User guide
Project User guide can be found in the [User Guide](./Documentations/user_guide/user_guide.md)

## List of changes
The list of changes can be found in the [ChangeLog](./CHANGELOG.md) file.

## Licenses
Almost all sources are under the <a href="https://opensource.org/license/BSD-3-clause/">BSD 3-Clause license</a>,
except sources inherit from external project like ARM, OASIS.

More details are available in the [SCR](./SW-Content-Register.txt) file.
