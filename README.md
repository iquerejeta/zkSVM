## zkSENSE prototype implementation

This repository contains the cryptographic operations needed to run zkSENSE. 
It is presented as part of the submission of the paper titled:

`zkSENSE: A Continuous Privacy-Preserving  Human Attestation Mechanism for Mobile Devices`

To run the experiments on an android device, we implemented a simple Android SDK that
ran this [example](./zkSENSE_rust_proof/examples/main.rs). 

*Disclaimer*: code is not production-ready.

### Contents:

- [Inner Product Zero Knowledge Proof](./inner_product_proof): 
Implementation of the extension of the [Inner Product Proof](https://github.com/dalek-cryptography/bulletproofs/blob/main/src/inner_product_proof.rs).

- [Pedersen Commitment Proofs](./pedersen_commitments_proofs): 
Implementation of the cryptographic tools used in zkSVM. In here 
we implement the algebraic proofs, containing the average, standard 
deviation, variance or diff proofs. Also, in here one can find the 
boolean proofs, containing the equality, opening or square proofs. 
Finally, this folder also contains the svm_proof, which leverages
all of the above to prove correct handling of a signed input vector. 

- [zkSENSE preprocessing](./zkSENSE_rust_proof): Implementation of 
the preprocessing required on an input vector (average, standard
deviation, variance) and an abstraction of the prover and verifier
of zkSVM. To run benchmarks of zkSVM, please see this folder. 

### Tests
To run tests, run
 
`cargo test`

in the corresponding folders. 

_Abstract_: Recent studies show that 20.4% of the internet traffic originates from automated agents. To identify and block such ill-intentioned traffic, mechanisms that verify the humanness of the user are widely deployed across the internet. CAPTCHA is the most popular among such mechanisms. Original CAPTCHAs require extra user effort (e.g., solving mathematical or image-based puzzles), which severely harms user’s experience, especially on mobile, and provide only sporadic verification of their humanness. More recent solutions like Google’s reCAPTCHA v3 leverage attestation data (e.g., user behavioral data, device fingerprints) shared with a remote server, thus raising significant privacy concerns.

To address all of the above, we present zkSENSE: the first zero knowledge proof-based humanness attestation system designed for mobile devices. Contrary to state-of-the-art systems, zkSENSE assesses humanness continuously on the background in a privacy preserving way. zkSENSE achieves that by classifying the motion sensor outputs of the mobile device based on a model trained by using both publicly available sensor data and data collected from a small group of volunteers. The classification result is enclosed in a zero knowledge proof of humanness that can be safely shared with an attestation service such as Privacy Pass.

We implement zkSENSE as an Android service to demonstrate its effectiveness and practicability. In our evaluation, we show that zkSENSE verifies the humanness of the users asynchronously, on the background, without degrading their experience or jeopardizing user privacy, while it achieves 92% accuracy across a variety of attack scenarios. On a two years old Samsung S9, each attestation takes around 3 seconds in total (when visual CAPTCHAs need 9.8 seconds) and consumes a negligible amount of battery.
