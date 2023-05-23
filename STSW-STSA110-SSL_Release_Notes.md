---
pagetitle: Release Notes for STSAFE-A1xx Middleware Component
lang: en
---

<center> <h1> Release Notes for **STSW-STSA110-SSL** </h1> </center>

<center> Copyright &copy; 2023 STMicroelectronics </center>

![](_htmresc\st_logo.png)

# Purpose
The STSW-STSA110-SSL software package can be used as an *OpenSSL®* engine (hardware support) or a C library for any
Linux application using the STSAFE-A110 hardware.. 

![](_htmresc/architecture_2.PNG)

The STSAFE-A110 is a highly secure solution that acts as a secure element providing authentication and data management services to a local or remote host. 
It consists of a full turnkey solution with a secure operating system running on the latest generation of secure microcontrollers. 
The STSAFE-A110 can be integrated in IoT (Internet of things) devices, smart-home, smart-city and industrial applications, consumer electronics devices, consumables and accessories.

**STSAFE-A110 Key Features**:

- Authentication (of peripherals, IoT and USB Type-C devices)

- Secure channel establishment with remote host including transport layer security (TLS) handshake 

- Signature verification service (secure boot and firmware upgrade) 

- Usage monitoring with secure counters

- Pairing and secure channel with host application processor 

- Wrapping and unwrapping of local or remote host envelopes

- On-chip key pair generation 




Here is the list of references to user documents:

- [ STSAFE-A110 Datasheet](https://www.st.com/resource/en/datasheet/stsafe-a110.pdf) : Authentication state-of-the-art security for peripherals and IoT devices

  

![STSAFE-A Logo](_htmresc\STSAFE_A_logo.png)



<div style="text-align:center">
    <h1>
        Update History
    </h1>
</div>



## V2.0 / 31-MARCH-2023

#### Main changes:

##### STSAFE-A110 SPL03 support

This release implements the following upgrades and fixes:

- Support of STSAFE-A110 SPL03 profile in addition to SPL02 profile supported in previous releases
- Compatibility with all *OpenSSL®* 1.1.1 versions in addition to *OpenSSL®* 1.1.1q supported in previous releases
- Delete the AWS™ connection example (deprecated)
- Addition of a CSR creation example
- Compatibility with STSW-SAFEA1-MW (STSAFE-A1xx Middleware) v3.3.6

#### Supported Devices and Boards:

The STSW-STSA110-SSL package is easily portable on any Linux environment.
It has been tested in applications developed for the following devices and boards:

- X-NUCLEO-SAFEA1 on Raspberry Pi 3 Model B board

#### Backward Compatibility:

There is backward compatibility with previous versions of STSW-SAFEA1-MW (STSAFE-A1xx Middleware)

#### Dependencies:

This software release is compatible with:

- All *OpenSSL®* 1.1.1 versions



## V1.0.0 / December-2020

#### Main changes:

##### First release 

**<u>Additional features :</u>**

###### Headline
First official version for STSAFE-A110 devices





------

For complete documentation on **STSAFE-A110** , visit:  [[STSAFE-A110 @ www.st.com](https://www.st.com/en/secure-mcus/stsafe-a110.html)]

This release note uses up to date web standards and, for this reason, should not be opened with Internet Explorer but preferably with popular browsers such as Google Chrome, Mozilla Firefox, Opera or Microsoft Edge.
