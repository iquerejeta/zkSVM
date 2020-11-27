## Pedersen Commitment Proofs
This repo contains all cryptographic material used in zkSVM excluding the 
Zero Knowledge Inner Product Proof, which is available [here](../inner_product_proof). 
These proofs are used to provably compute the preprocessing to the signed vectors. 
We name algebraic proofs the proofs of average, standard deviation, variance or difference,
which are available [here](./src/algebraic_proofs).
We name boolean proofs the proofs of equality, knowledge of opening or square relation, 
which are available [here](./src/boolean_proofs). 
Finally, we leverage the above to generate the complete proof that the sensor vector has 
been applied the correct pre-processing. It is available [here](./src/svm_proof). 