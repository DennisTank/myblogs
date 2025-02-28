# Computer Security
The protection given to an automated information system in order to attain the applicable objectives of preserving the integrity, availability, and confidentiality of information system resources (includes hardware, software, firmware, information/data, and telecommunications).

# Adversaries
- Hackers 
- Employees (both malicious and unintentional)
- Terrorists groups
- Governments
- Opposing Industries

# Security Property
- **Confidentiality**: Preserving authorized restrictions on information access and disclosure, including means for protecting personal privacy and proprietary information. A loss of confidentiality is the unauthorized disclosure of information.
- **Integrity**: Guarding against improper information modification or destruction, including ensuring information nonrepudiation and authenticity. A loss of integrity is the unauthorized modification or destruction of information.
- **Availability**: Ensuring timely and reliable access to and use of information. A loss of availability is the disruption of access to or use of information or an information system.

> It is also called CIA triad

- **Authenticity**: The property of being genuine and being able to be verified and trusted; confidence in the validity of a transmission, a message, or message originator. This means verifying that users are who they say they are and that each input arriving at the system came from a trusted source.
- **Accountability**: The security goal that generates the requirement for actions of an entity to be traced uniquely to that entity. This supports nonrepudiation, deterrence, fault isolation, intrusion detection and prevention, and after-action recovery and legal action. Because truly secure systems are not yet an achievable goal, we must be able to trace a security breach to a responsible party. Systems must keep records of their activities to permit later forensic analysis to trace security breaches or to aid in transaction disputes.

### **Threat**
A potential for violation of security, which exists when there is a circumstance, capability, action, or event, that could breach security and cause harm. That is, a threat is a possible danger that might exploit a vulnerability. 

### **Vulnerability**
A flaw or weakness in a system’s design, implementation, or operation and management that could be exploited to violate the system’s security policy.

### **Attack**
An assault on system security that derives from an intelligent threat; that is, an intelligent act that is a deliberate attempt (especially in the sense of a method or technique) to evade security services and violate the security policy of a system.

### **Countermeasure**
An action, device, procedure, or technique that reduces a threat, a vulnerability, or an attack by eliminating or preventing it, by minimizing the harm it can cause, or by discovering and reporting it so that corrective action can be taken.

- **Prevent**: By blocking the attack or closing the vulnerability
- **Deter**: By making the attack harder but not impossible
- **Deflect**: By making another target more attractive
- **Mitigate**: By making its impact less severe
- **Recover**: By restoring to the state of before the attack

### **Risk**
An expectation of loss expressed as the probability that a particular threat will exploit a particular vulnerability with a particular harmful result.

Three factors to consider:
- Attractiveness of the system
- Value of the system
- Accessibility of the system


# Attack Types
- **Network attack surface**: This category refers to vulnerabilities over an enterprise network, wide-area network, or the Internet. Included in this category are network protocol vulnerabilities, such as those used for a denial-of-service attack, disruption of communications links, and various forms of intruder attacks.
- **Software attack surface**: This refers to vulnerabilities in application, utility, or operating system code. A particular focus in this category is Web server software.
- **Human attack surface**: This category refers to vulnerabilities created by personnel or outsiders, such as social engineering, human error, and trusted insiders.


### Sniffing Attack

Sniffing attack in context of network security, corresponds to theft or interception of data by capturing the network traffic using a packet sniffer. When data is transmitted across networks, if the data packets are not encrypted, the data within the network packet can be read using a sniffer.

Promiscuous mode is used to monitor(sniff) network traffic. Typically, promiscuous mode is used and implemented by a snoop program that captures all network traffic visible on all configured network adapters on a system.

Tools: TCPDump, Wireshark

### Password Cracking

Guessing the Password.
Exhaustive search or Brute force attack is when the attacker try to guess the password multiple time till it gets the true password.

Dictionary attacks is a type of Brute force attack where the guessing is done by a wordlist file. The wordlist mostly contains the most used password combinations.

Tools: AirCrack and AirSnort, JohnTheRipper

### Malware

It is a malicious software.

A user can get infected by:
- Running a program
- Opening an email attachment or file
- Visiting a web site
- Copying a file from a USB

Types:
- **Ransomware**: software which sends or shows fake messages to victim to get ransom money from the victim. Scareware is an alternative.
- **Spyware**: a software which sends victims data to spy or attacker.
- **Trojan**: A Trojan Horse Virus is a type of malware that downloads onto a computer disguised as a legitimate program. The delivery method typically sees an attacker use social engineering to hide malicious code within legitimate software to try and gain users' system access with their software.
- **Virus**: A computer program that can copy itself and infect a computer without permission or knowledge of the user. A virus might corrupt or delete data on a computer, use internet based programs to spread itself to other computers, or even erase everything on a hard disk.
- **Worm**: A computer worm is a type of malware whose primary function is to self-replicate and infect other computers while remaining active on infected systems. A computer worm duplicates itself to spread to uninfected computers.

> A worm can self-replicate and spread to other computers, while a virus cannot. A virus needs to be sent from one computer to another by a user or via software.

### Botnet

A botnet (short for “robot network”) is a network of computers infected by malware that are under the control of a single attacking party, known as the bot-master. Each individual machine under the control is known as a bot.  Botnets can be used to perform Distributed Denial-of-Service attacks, steal data, send spam, and allow the attacker to access the device and its connection. The bot-master can control the botnet using command and control software.
### Phishing

Phishing is **a form of social engineering and scam where attackers deceive people into revealing sensitive information or installing malware such as ransomware**.

### Vulnerabilities Exploitation

An exploit is a program, or piece of code, designed to find and take advantage of a security flaw or vulnerability in an application or computer system, typically for malicious purposes such as installing malware. An exploit is not malware itself, but rather it is a method used by cybercriminals to deliver malware.

### Denial of Service Attacks

A DoS (denial-of-service) attack is **a cyberattack that makes a computer or other device unavailable to its intended users**. This is usually accomplished by overwhelming the targeted machine with requests until normal traffic can no longer be processed.

### Social Engineering

 Social engineering refers to all techniques aimed at talking a target into revealing specific information or performing a specific action for illegitimate reasons

### IP Spoofing

IP spoofing, or IP address spoofing, refers to **the creation of Internet Protocol (IP) packets with a false source IP address to impersonate another computer system**. IP spoofing allows cybercriminals to carry out malicious actions, often without detection.

Tor is an example.

Source Routing, also called path addressing, allows a sender of a packet to partially or completely specify the route the packet takes through the network. In contrast, in conventional routing, routers in the network determine the path incrementally based on the packet's destination.

Blind Attack is a type of network-based attack method that does not require the attacking entity to receive data traffic from the attacked entity**; i.e., the attacker does not need to "see" data packets sent by the victim. For example, SYN flood attack and Dos Attack.
### Stages of A Cyber Attack

1. **Reconnaissance**: Before launching an attack, hackers first identify a vulnerable target and explore the best ways to exploit it. The attacker is looking for a single point of entry to get started.
2. **Scanning**: Once the target is identified, the attacker attempts to identify a weak point that allows him or her to gain access. Often, this step progresses slowly as the attacker searches for vulnerabilities.
3. **Exploitation**: This phase of the cyber attack lifecycle enacts the weaponization stage once the exploit is deployed in the network, system, or code. This stage’s success is the adversary’s first entry into the organization, similar to gaining a foothold on a beach and turning it into a staging area.
4. **Access Maintenance**: Once a weak spot is discovered, the next step is to gain access and then escalate privileges to allow the attacker to move freely within the environment. Once the attacker has access and privileges are escalated, they have effectively taken over your system.
5. **Exfiltration**: Now that the attacker can freely move around the network, he / she can now access systems with an organization’s most sensitive data and take his / her time extracting it.
6. **Identification Prevention**: Stay Anonymous.

### Hacking Terminology

- **White hat hackers** (Ethical hacker or sneaker): good ones
- **Black hat hackers** (Cracker): bad ones
- **Gray hat hackers**: do illegal hacking with good intentions; organizations
- **Script Kiddie**: Individual with no technical knowledge; hacking using tools.
### Security Terminology

- **Firewall**: A Firewall is a network security device that monitors and filters incoming and outgoing network traffic based on an organization's previously established security policies.
- **Intrusion Detection**: An intrusion detection system (IDS) is a device or software application that monitors a network for malicious activity or policy violations. Any malicious activity or violation is typically reported or collected centrally using a security information and event management system.
- **Access Control**: Access control is a data security process that enables organizations to manage who is authorized to access corporate data and resources. Secure access control uses policies that verify users are who they claim to be and ensures appropriate control access levels are granted to users.
- **Non-repudiation**:Non-repudiation is the assurance that someone cannot deny the validity of something. Non-repudiation is a legal concept that's widely used in information security and refers to a service, which provides proof of the origin and integrity of data.
- **Least-privileges**: Least access control.


# Cryptography
## Why Encryption/Decryption?
Required for insecure channels.
Goals of Cryptography:
- Ensure security of communication over insecure medium
- Confidentiality
- Integrity
- Authenticity

### Encryption
Encryption is the process of encoding a message so that its meaning is not obvious.
### Decryption
Decryption is the reverse process, transforming an encrypted message back into its normal, original form.
### Cryptosystem
A system for encryption and decryption is called a cryptosystem.
#### Plaintext:
Readable message before encryption
#### Ciphertext:
Not readable message after encryption
#### Encryption/Decryption algorithm (function):
The cryptosystem involves a set of rules for how to encrypt the plaintext and how to decrypt the ciphertext
#### Key:
A sequence of symbols or numbers used by an algorithm to alter information & make that information secure
#### Cryptanalysis:
Cryptanalysis is an attempt to break the ciphertext

# Classic Cipher Techniques

## Substitution Techniques
Substituting the bits or letters in the encryption and decryption, by using a predefined table or set of rules in an algorithm.
Example: Caesar cipher, Atbash cipher, Multi-alphabet substitution, Vigenère

## Transposition Techniques
Changing the positions of the bits or letters in the encryption or decryption, by using an algorithm.
Example: Rail Fence cipher, Columnar transposition, Route cipher, Double Transposition

## Stream-based Ciphers
- One at a time
- The keys also come one by one 
- The key stream is hard to guess
- Mixes plaintext with key stream
- Good for real-time services
![[Pasted image 20230916170632.png]]

## Block Ciphers
- Iterated encryption in multiple rounds
- Plaintext is split into blocks and then encrypt each block
- Substitution and transposition

## Symmetric Key Encryption

Data Encryption Standard (DES) (1970s)
International Data Encryption Algorithm (IDEA) (1991)
Blowfish (Open Source) (1993)
Advance Encryption Standard (AES) (2001) (Still being used widely) 
All above use the Combination of Substitution and Transposition

![[Pasted image 20230916171244.png]]

![[Pasted image 20230916171429.png]]
![[Pasted image 20230916171600.png]]

## Asymmetric Key Encryption

![[Pasted image 20230916172050.png]]


- Rivest Shamir Adleman (RSA): Encryption Public key for encryption, private key for decryption.
- Digital Signature Algorithm (DSA): Private key for encryption, public key for verification.


### RSA
Extensive cryptanalysis has been done, and no serious flaws have been found yet.

Algorithm is based on the underlying problem of factoring large numbers.

1. Select two large prime numbers, $x$ and $y$. The prime numbers need to be large so that they will be difficult for someone to figure out.
2. Calculate $n$=$x$ x $y$
3. Calculate the _**totient**_ function; 
$$ϕ(n)=(x−1)(y−1)$$
4. Select an integer $e$, such that $e$ is _**co-prime**_ to $ϕ(n)$ and $1< e < ϕ(n)$.
> The pair of numbers $(n,e)$ makes up the public key.

5. Calculate $d$ such that
$$ e.d = 1 \modϕ(n) $$
> The pair $(n,d)$ makes up the private key.

> $d$ can be found using the _**Extended Euclidean Algorithm**_.

```
def GCD(a, b):
    if a == 0:
        return b

    return GCD(b%a, a)
```

### Diffie-Hellman
Allow two parties to establish a shared key over an insecure channel.

Person1 creates three numbers: $a ,S,P$.
Person1 calculates $A$:
$$A = S^a\mod P$$
Person1 sends: $S,P,A$.

Person2 creates: $b$
Person2 calculates $B$:
$$B=S^b \mod P$$
Person2 sends back: $B$

Now, both calculate the key $K$:
$$K=A^b \mod P$$
$$K=(S^a\mod P)^b \mod P$$
$$K=S^{ab} \mod P$$
$$K=(S^b\mod P)^a \mod P$$
$$K=B^a \mod P$$

### DSA
Federal Information Processing Standard for digital signatures.
Use private key to generate a signature on the hash of the message
Use public key to verify message
DSA provides:
- Sender authentication
- Verification of message integrity
- Nonrepudiation
One-Way Hash has a fixed length, no matter what the size of data is.

## Hybrid Cryptography
In real world both symmetric crypto and asymmetric crypto are used in communication encryption
- RSA is used for exchanged session keys
- AES is used to encrypt/decrypt data packets through session keys

# Public Key Infrastructure
A solution is to do public key certification.
- A secure public key infrastructure is necessary
- Assures identity to users
- Provides key management features

**Components**:
- Digital Certificates
- Certificate Authorities
- Registration Authorities
- Validation Authorities
- Certificate Revocation List (CRL) ( DigiNotar and Comodo )

# Secured Protocols
- TLS (SSL): Transport Layer Security (Secure Socket Layer)
- SSH: Secure Shell
- SFTP: SSH File Transportation Protocol
- VPN: Virtual Private Network
- HTTPS: Hypertext Transfer Protocol Secure