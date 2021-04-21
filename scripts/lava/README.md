# YAML templates

This directory contains YAML templates that are concatenated to produce a YAML file used to run Security Middleware test using LAVA automated validation tool.
The Security Middleware bash script scripts/smw_squad.sh is used to prepare the final YAML file function of the type of tests and the target.

## smw_setup.yaml or smw_setup_uuu.yaml
This file defines the setup to configure the platform to be tested.

## smw_package.yaml
This file describes the commands to be executed to download and install a SMW package.

## smw_ctest.yaml
This file describes the commands to be executed to run the tests on target.
