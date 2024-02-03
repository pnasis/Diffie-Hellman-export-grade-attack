# Diffie-Hellman export grade attack

The **Diffie-Hellman export grade attack** refers to a security vulnerability associated with the use of weak key lengths in the Diffie-Hellman key exchange protocol. This vulnerability primarily affected systems that implemented export-grade cryptography during the 1990s, as mandated by the U.S. government's export regulations on cryptographic software and hardware. \
\
During that time, the U.S. government imposed restrictions on the export of strong cryptographic algorithms, considering them as munitions. As a result, many products were limited to using key lengths of 512 bits or less for encryption, which was significantly weaker than the standard key lengths used for secure communications. \
\
The **Diffie-Hellman key exchange** allows two parties to establish a shared secret key over an insecure communication channel. However, when implemented with weak key lengths, it became susceptible to attacks. The limited key length made it easier for attackers to perform brute-force attacks, where they could potentially try all possible key combinations within a feasible amount of time. \
\
In 2015, the **Logjam attack** highlighted the risks associated with export-grade cryptography, including Diffie-Hellman key exchange. Logjam exploited the fact that many servers and clients were still supporting weak, export-grade Diffie-Hellman parameters. The attackers could perform precomputation and build a large database of potential keys, making it easier to break the encryption. \
\
To mitigate the risks associated with the Diffie-Hellman export grade attack, it is crucial to use strong key lengths and avoid the use of export-grade cryptographic algorithms. System administrators and developers should ensure that their systems are configured with secure cryptographic parameters to protect against potential attacks. In recent years, there have been efforts to deprecate and eliminate support for export-grade cryptography in various protocols and applications.

## About
The following program is created for a CTF crypto challenge in [CryptoHack](https://cryptohack.org/) associated with the DH_EXPORT attack. It automatically performs a man-in-the-middle attack, where an unauthorized entity intercepts and alters the communication between two parties (Bob and Alice). As a result, it is capable of downgrading the encryption and solving the discrete log problem, ultimately obtaining the flag.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the required packages.

```bash
pip3 install pwntools pycryptodome
```

Also [Sagemath](https://www.sagemath.org/) is required for solving the discrete log problem.

## Usage

```bash
python3 export-grade.py
```

## Contributing

Pull requests are welcome. **For major changes, please open an issue first
to discuss what you would like to change.**

## License

>This project is under [Apache 2.0](https://choosealicense.com/licenses/apache-2.0/) licence.
