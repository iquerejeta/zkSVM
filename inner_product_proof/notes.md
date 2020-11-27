### Notes on how to implement zkSENSE exclusively with inner product proofs

#### Step 1 
Calculate the pre-image of the pedersen hashes. For this we are evaluating pedersen verify in threes as follows: 

- (acc_x_pad_zeros, acc_y_pad_zeros, acc_z_pad_zeros)
- (acc_x_pad_zeros_sec_2, acc_y_pad_zeros_sec_2, acc_z_pad_zeros_sec_2)
- (gyr_x_pad_zeros, gyr_y_pad_zeros, gyr_z_pad_zeros)
- (gyr_x_pad_zeros_sec_2, gyr_y_pad_zeros_sec_2, gyr_z_pad_zeros_sec_2)

Furthermore, for each threes, we need to calculate 11 hashes, given that the function of ZoKrates is limited. 
For this, in our new implementation, we could work directly with the Pedersen Hashes, reducing the overhead of
a total of 44 Pedersen pre-images proofs.

 Then we produce proofs of the average and standard deviation for each of the vectors. Similarly, we use a 
 variable that is 'diff' which must be define what it is:
 
 Let *x* be a vector. Then *x_diff* is defined by 
 
 x_diff = (x[0] - x[1], x[1] - x[2],..., x[n] - 0)
 
 We evaluate standard deviation and averages over this as well. 
 
 #### Step 2
 
We proceed by proving that certain linear operations made to the average and standard deviation satisfy a value. 