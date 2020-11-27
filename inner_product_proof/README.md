## Zero Knowledge Inner Product Proof
This repo extends the design presented in the Bulletproofs [paper](https://eprint.iacr.org/2017/1066.pdf)
and implemented [here](https://github.com/dalek-cryptography/bulletproofs). 

The proof presented in the Bulletproofs paper does not have (nor it intends to) the zero knowledge
property, meaning that it discloses some information of the vectors whose inner product
is being proven. That is fine for their construction, but for zkSENSE we need to have the 
Zero Knowledge property when leveraging the Inner Product Proof.

This repo is a fork of Henry de Valence, Cathie Yun, and Oleg Andreev's Bulletproofs implementation, 
removing the dispensable code for zkSENSE, and extending the Inner Product Proof. One can find the 
latter in [`/src/ip_zk_proof`](./src/ip_zk_proof/).  