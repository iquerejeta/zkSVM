## zkSENSE prototype implementation

This repository contains the cryptographic operations needed to run zkSENSE. 
It is presented as part of the submission of the paper titled:

`zkSENSE: A Friction-less Privacy-Preserving Human Attestation Mechanism for Mobile Devices`

To run the experiments on an android device, we implemented a simple Android SDK that
ran this [example](./zkSENSE_rust_proof/examples/main.rs). Rust nightly is required to
run the experiments. 

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
 
`cargo +nightly test`

in the corresponding folders. 

_Abstract_: Recent studies show that 20.4\% of the inter-net traffic 
originates from automated agents. To identify and block such 
ill-intentioned traffic, mechanisms that _verify the humanness of the 
user_ are widely deployed, with CAPTCHAs being the most popular. 
Traditional CAPTCHAs require extra user effort (e.g., solving 
mathematical puzzles), which can severely downgrade the end-user’s 
experience, especially on mobile, and provide sporadic humanness 
verification of questionable accuracy. More recent solutions like 
Google’s reCAPTCHA v3, leverage attestation data (e.g., user behavioral 
data, device fingerprints) shared with a third-party server, thus 
raising significant privacy concerns. 

To address these issues, we 
present zkSENSE: the first zero-knowledge proof-based humanness 
attestation system designed for mobile devices. zkSENSE moves the 
human attestation to the edge: onto the user’s very own device, where 
humanness of the mobile user is assessed in a privacy-preserving and 
seamless manner. zkSENSE achieves this by classifying motion sensor 
outputs of the mobile device, based on a model trained by using both 
publicly available sensor data and data collected from a small group 
of volunteers. To ensure the integrity of the process, the 
classification result is enclosed in a proof of humanness, which 
consists of zero knowledge proofs that can be safely shared with a 
remote server. We implement zkSENSE as an Android service to demonstrate 
its effectiveness and practicality. In our evaluation, we show that 
zkSENSE successfully verifies the humanness of a user without 
jeopardizing their experience or privacy. On a two years old Samsung S9,
zkSENSE’s attestation takes around 3 seconds (when visual CAPTCHAs need 
9.8 seconds) and consumes a negligible amount of battery. We also 
stress test zkSENSE across a variety of attacking scenarios,including 
a real device docked on a swinging cradle, and demonstrate 92\% accuracy.