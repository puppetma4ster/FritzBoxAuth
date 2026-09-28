# FRITZ!Box Passwort UI extractor and recovery
This repository explains how password authentication works on the FritzBox login interface, how to extract hashes,
and how to calculate them.

## Introduction
To prevent plaintext transmission of credentials over HTTP, the FritzBox login uses a challenge-response mechanism.
From FRITZ!OS 7.24 onward, a PBKDF2-HMAC-SHA256-based scheme is used by default. 
Older versions use an MD5-based challenge-response scheme.
In both cases, the server provides a challenge as part of the initial login page response. 
The client then derives a response value from the user password and the received challenge,
which is submitted during the login attempt.
```commandline
const data = {"firstTenMin":false,"challenge":"2$60000$f1daf2c6bf6d02429df3b2e85acda7fe$6000$44297fd0839e1e579955b32e4ca19396"
```
After the user enters the password and initiates the login process,
the client computes a challenge-response value using the previously received challenge and the provided password.
This derived response is then submitted to the server via an HTTP POST request to /index.lua.
```commandline
Form item: "response" = "44297fd0839e1e579955b32e4ca19396$1b939aea364ecd3fbe335e4ccfcecf07d0e508b853af9812ed884538517d6733"
    Key: response
    Value: 44297fd0839e1e579955b32e4ca19396$1b939aea364ecd3fbe335e4ccfcecf07d0e508b853af9812ed884538517d6733
```
## PBKDF2-based scheme
The use of the PBKDF2-based authentication scheme is indicated by the challenge prefix.
If the challenge string starts with "2$", the PBKDF2-HMAC-SHA256-based mechanism is used.

### Challenge structure
The challenge is structured as follows:
```commandline
challenge = <Version>$<IterationNumber1>$<Salt1>$<IterationNumber2>$<Salt2>
```
> [NOTE]
> Observations indicate that salt2 changes on each login attempt,
> while the remaining parameters remain constant within repeated tests on the same device.
>
> It is currently unclear whether the static parameters are:
> - fixed per device (FritzBox instance-specific), or
> - constant across firmware versions.

### Hashing algorithm
The key derivation works as follows:
\<hash1\> = pbkdf2_hmac_sha256(\<password\>, \<salt1\>, \<iter1\>)
<response> = <salt2>$ + pbkdf2_hmac_sha256(\<hash1\>, \<salt2\>, \<iter2\>)




## MD5-based scheme
The MD5-based scheme is indicated by an 8-character hexadecimal challenge, unlike the PBKDF2-based scheme, which uses a challenge starting with "2$".
### Challenge structure
The challenge in MD5-based verification consists of an 8-character hex string:
```commandline
challenge = <salt>
Example: f7719497
```
A unique challenge is generated for every login attempt

### Hashing algorithm
coming soon...

## Program usage
The program currently provides two main functions:
1. Extraction of FritzBox authentication hashes from PCAPNG files
2. Password recovery using a wordlist-based approach

Both processes are implemented in Python and are not optimized for performance,
resulting in comparatively slow execution. This implementation is intended as a proof of concept rather than a production-grade tool.

On an Intel Core i7-11370H (11th generation), the current implementation achieves approximately 5,000 hash evaluations per minute under the tested configuration.

### Extraction
To extract hashes from a capture file, use the following command:
```commandline
fbhash extract -o hashes ~/Password.pcapng
```
The "-o" is the output flag that specifies where the hashes should be saved

Hashes are stored in the following format:
```commandline
 <Iteration1>:<Salt1>:<Iteration2>:<Salt2>:<Hash>
```
### Cracking
To recover the hashlist, use:
```commandline
    fbhash crack -w wordlist.txt fritzBox.hashes 
```


## Todo
- writing a hashcat module for cracking FritzBox hashes
- writing a JTR module for cracking FritzBox hashes

## Disclaimer
This project is intended for educational and research purposes only. 
It is designed to demonstrate and analyze authentication mechanisms in a controlled environment.

The author does not assume any responsibility for misuse of the software or for any damages resulting from its use.


## References
In depth explanation of the FritzBox Web UI authentication process

https://fritz.support/resources/HTTP_Session-ID_EN.pdf