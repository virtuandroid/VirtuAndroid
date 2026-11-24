# Introduction

We welcome all contributions to VirtuAndroid!  

You can help this project by contributing code, but also by reporting issues, 
reporting vulnerabilities, localizing the project or simply contributing with ideas.

However, to facilitate a productive and welcoming open source environment we strongly urge you to read 
these contributing guidelines. They are quick to read through, and should be easy to follow.

# Ground Rules

## Be respectful

Open sources projects are built by people for people; and in the end people deserve respect. 
Therefore, please respect and be kind to each other. At the other end of the screen is another human.

## Keep discussions and code in English

This is an international project, wherein everyone should be able to partake. Therefore
we decided to keep all communication in English to make the project as accessible as possible. 
We understand that not everyone is fluent in English, that is okay. You may use translation tools
such as [Google Translate](https://translate.google.com/) or [DeepL](https://www.deepl.com/).

## Always state AI contributions

Artificial Intelligence can be very helpful to accomplish many tasks in this project. It can be useful
when implementing features, performing security scans, increasing app compatibility or simply fixing bugs.
However, for the sake of clarity in discussions **please state AI contributions**. You are allowed to "vibe-code"
contributions, but we need to know if AI was used, and how it was used.

# Getting started

Please read the [VirtuAndroid wiki](https://github.com/virtuandroid/VirtuAndroid/wiki) page before getting started.
It contains information on how this project was started, and why we made certain design decisions.
It can also be a great resource for understanding the internals of the project. The wiki page was written to 
be understandable for anyone with an Android background.

# How to report a bug

If you find a security vulnerability, do NOT open an issue. Create a new security advisory [here](https://github.com/virtuandroid/VirtuAndroid/security/advisories).

If you want to report a bug then create an [issue](https://github.com/virtuandroid/VirtuAndroid/issues) containing everything needed to reproduce the bug.
We cannot fix the bug unless we can reproduce the bug.

For example, if an app crashes, then please submit:
- App version
- The app APK
- A list of actions to trigger the crash

Additionally, we would very much appreciate: 

- A Logcat containing the crash
- A video showing how the crash can be reproduced

# Code review process

We perform thorough reviews to ensure that no security vulnerabilities or bugs are introduced by new code.
This may be daunting by first-time contributors, but we will try to help if any issues are found.

## Code guidelines
This project is written in Java, but we seek to migrate the code base to Kotlin as 
per the [Kotlin-first initiative](https://developer.android.com/kotlin/first). 
Therefore when contributing new code, try to use Kotlin when possible. Additionally, avoid 
use of deprecated, or too new methods if possible. We aim to make this project future-proof and 
fully-featured across all supported Android versions. 
