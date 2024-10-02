## FM_dylib_checker

This command line utility was designed to check dylib hijack vulnarability of FileMaker Pro under macOS

https://support.claris.com/s/article/FileMaker-Security-Information?language=en_US

https://www.cve.org/CVERecord?id=CVE-2023-42920


## Why do you need it

Typically, each FileMaker developer has several versions of the application installed, from oldest to newest.

In addition, many have used runtime in the past to generate custom FileMaker-based applications. 

How do you determine if you have dylib vulnerable versions on your Mac ? 

Answering this question is not so easy, as the vulnerability kept appearing and disappearing from version to version.

## How to use

Download `FM_dylib_checker.dmg` from release folder, mount and run FM_dylib_checker 

You can also download Xcode project and build it from source.

## Example of output