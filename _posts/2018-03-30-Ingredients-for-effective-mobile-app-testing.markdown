---
layout: post
title: "Ingredients for effective mobile app testing"
date: 2018-03-30 16:00:00 +0100
tags: mobile security review
---


From small note taking apps to critical financial apps, mobile apps are augmenting our daily lives. The presence of mobile apps is undeniably increasing and so is the demand for mobile app security.

Are you looking for efficient and effective mobile app testing? I compiled a few ingredients targeted at security reviewers and businesses requesting mobile app security reviews. 


## 1) Discuss and define the security requirements
Security requirements changes depending on the type and nature of the mobile application. Taking data leakage threats as an example; mobile apps can leak data in different ways through system logs, backups and caching to name a few. Zooming into caching issues, mobile libraries and frameworks usually cache web requests and responses by default for performance gain. Apps with a higher security requirement usually opt to disable, clear or in some cases encrypt the cache. This introduces a certain complexity that businesses with a less strict security requirement might not want to deal with. 

The [OWASP AppSec Verification Standard (MASVS)][owasp-masvs] is a good starting point to define the security requirements as it provides a security model with a variety of security levels.
Well defined security requirements result into a better scope definition which leads to a more focussed and streamlined security review. OWASP also has an [extensive mobile checklist][owasp-mobile-checklists] worth to be mentioned.


## 2) Whitebox over blackbox testing
Opt for a whitebox security review by making the source code and documentation available to the security reviewer. Reverse engineering is a daunting task especially if the apps are heavily obfuscated and contain anti hooking/reversing mechanisms. This results into wasted time that can span from a few days to several weeks depending on the size and complexity of the mobile app. It is more effective to spend this time into actual and potential security threats hidden in mobile apps. Certain security issues are easier to spot from source.

One exception that can be thought of is resilience against reverse engineering. This might be a research question on its own. A greybox approach is not unheard of in such cases. 


## 3) Ideal security testing environment
Mobile apps usually make use of a backend. It goes without saying that the security test should ideally be performed in a test environment separated from production data.

Here are a few points that might increase the overall efficiency of the security engagement and that should be communicated to the party requesting a security review:
- Make sure to have several test accounts with different roles. Depending on the business logic, sometimes accounts need to go through long and tiresome enrolment process (several hours). It is therefore best if there are a few accounts that are already enrolled ready to be used.
- Security reviewers should be able to perform the test autonomously. It happened that some apps made use of Two-Factor Authentication (2FA) and the verification code was sent to the developers instead. This creates unnecessary overhead which resulted in hours of wasted time. The developer either was having a break, was in a meeting or simply too busy working on other projects. Best surprise when you receive an automatic out-of-office mail that the developer is on vacation.
- Make sure to have sufficient prepopulated test data. Manually inserting test data is boring and a waste of time. Make sure to automate this.
- Possess several different test builds with a variety of security settings. Ideally the security reviewer should be able to manually enable or disable such settings. Think about root/jailbreak detection, TLS pinning, device binding, logging etc... Sometimes testing the backend is in the testing scope which requires intercepting and modifying the traffic between the mobile app and the backend. Once the security reviewer has assessed that the connection is sufficiently secured and hardened, it saves time by temporarily disabling such security measures.


[owasp-masvs]: https://github.com/OWASP/owasp-masvs/releases/
[owasp-mobile-checklists]: https://github.com/OWASP/owasp-mstg/tree/master/Checklists