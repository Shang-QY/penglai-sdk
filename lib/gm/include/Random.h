/************************************************************************
  Copyright (c) IPADS@SJTU 2021. All rights reserve.

  This file contains the pseudo-random generator provided by PENGLAI sdk.
  It is used to generate 'seed' for SM2, and it can be used to generate
  'key' and 'iv' for SM4.

  Function List:
    1.penglai_set_rand_seed             //set random seed
    2.penglai_read_rand                 //generate a random
**************************************************************************/

#pragma once

/**
 * User must set a real random as random number seed, otherwise
 * function penglai_read_rand() just output the same result each
 * time the random system initialized.
 * @param seed              A real random number please.
 * @return                  Null
 */
void penglai_set_rand_seed(unsigned int seed);

/**
 * Generate a random number with 'size' bytes length. It can be
 * used to generate Key and IV in symmetric encryption and so on.
 * If random seed haven't been set, it will be set as 0.
 * @param rand              Random output
 * @param size              Length of pre allocated 'rand'
 */
void penglai_read_rand(unsigned char rand[], int size);
