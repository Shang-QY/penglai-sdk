/************************************************************************
  Copyright (c) IPADS@SJTU 2021. Modification to support Penglai (RISC-V TEE)

  This file contains implementation of SM2 signature algorithm and verification
  algorithm, part of codes provided by the Commercial Cryptography Testing Center,
  see <http://www.scctc.org.cn> for more infomation.

  Function List:
    1.SM2_Init                  //initiate SM2 curve
    2.Test_Point                //test if the given point is on SM2 curve
    3.Test_PubKey               //test if the given public key is valid
    4.Test_Zero                 //test if the big x equals zero
    5.Test_n                    //test if the big x equals n
    6.Test_Range                //test if the big x belong to the range[1,n-1]
    7.SM2_KeyGeneration         //generate SM2 key pair
    8.SM2_Sign                  //SM2 signature algorithm
    9.SM2_Verify                //SM2 verification
    10.SM2_SelfCheck()          //SM2 self-check
    11.SM3_256()                //this function can be found in SM3.c and SM3.h

  Additional Functions Added By PENGLAI Enclave:
    1.MIRACL_Init               //init miracl system
    2.SM2_make_prikey           //generate a SM2 private key
    3.SM2_make_pubkey           //generate a SM2 public Key out of a private Key
    4.SM2_gen_random            //generate a random number K lies in [1,n-1]
    5.SM2_compute_ZA            //compute ZA out of a given pubkey
**************************************************************************/

#pragma once

#define SM2_WORDSIZE 8
#define SM2_NUMBITS  256
#define SM2_NUMWORD  (SM2_NUMBITS / SM2_WORDSIZE)

#define ERR_ECURVE_INIT       0x00000001
#define ERR_INFINITY_POINT    0x00000002
#define ERR_NOT_VALID_POINT   0x00000003
#define ERR_ORDER             0x00000004
#define ERR_NOT_VALID_ELEMENT 0x00000005
#define ERR_GENERATE_R        0x00000006
#define ERR_GENERATE_S        0x00000007
#define ERR_OUTRANGE_R        0x00000008
#define ERR_OUTRANGE_S        0x00000009
#define ERR_GENERATE_T        0x0000000A
#define ERR_PUBKEY_INIT       0x0000000B
#define ERR_DATA_MEMCMP       0x0000000C

/****************************************************************
  Function:         SM2_make_pubkey
  Description:      calculate a pubKey out of a given priKey
  Calls:
  Called By:        SM2_KeyGeneration()
  Input:            priKey       // a big number lies in[1,n-2]
  Output:           pubKey       // pubKey=[priKey]G
  Return:           0: success
                    2: a point at infinity
                    5: X or Y coordinate is beyond Fq
                    3: not a valid point on curve
                    4: not a point of order n
  Others:
****************************************************************/
int SM2_make_pubkey(unsigned char PriKey[], unsigned char Px[], unsigned char Py[]);

/****************************************************************
  Function:         SM2_KeyGeneration
  Description:      generate a priKey and calculate a pubKey out of it
  Calls:            SM2_make_pubkey()
  Called By:        SM2_SelfCheck()
  Input:            priKey       // a big number lies in[1,n-2]
  Output:           pubKey       // pubKey=[priKey]G
  Return:           0: success
                    2: a point at infinity
                    5: X or Y coordinate is beyond Fq
                    3: not a valid point on curve
                    4: not a point of order n
  Others:
****************************************************************/
int SM2_KeyGeneration(unsigned char PriKey[], unsigned char Px[], unsigned char Py[]);

/****************************************************************
  Function:         SM2_Sign
  Description:      SM2 signature algorithm
  Calls:            SM2_Init(),Test_Zero(),Test_n(), SM3_256()
  Called By:        SM2_SelfCheck()
  Input:            message     //the message to be signed
                    len         //the length of message
                    d           //the private key
  Output:           R,S         //signature result
  Return:           0: success
                    1: parameter initialization error;
                    4: the given point G is not a point of order n
                    6: the signed r equals 0 or r+rand equals n
                    7 the signed s equals 0
  Others:
****************************************************************/
int SM2_Sign(unsigned char *message, int len, unsigned char d[], unsigned char R[], unsigned char S[]);

/****************************************************************
  Function:         SM2_Verify
  Description:      SM2 verification algorithm
  Calls:            SM2_Init(),Test_Range(), Test_Zero(),SM3_256()
  Called By:        SM2_SelfCheck()
  Input:            message     //the message to be signed
                    len         //the length of message
                    Px,Py       //the public key
                    R,S         //signature result
  Output:
  Return:           0: success
                    1: parameter initialization error;
                    4: the given point G is not a point of order n
                    B: public key error
                    8: the signed R out of range [1,n-1]
                    9: the signed S out of range [1,n-1]
                    A: the intermediate data t equals 0
                    C: verification fail
  Others:
****************************************************************/
int SM2_Verify(unsigned char *message, int len, unsigned char Px[], unsigned char Py[], unsigned char R[], unsigned char S[]);

/****************************************************************
  Function:         SM2_SelfCheck
  Description:      SM2 self check
  Calls:            SM2_Init(), SM2_KeyGeneration,SM2_Sign, SM2_Verify,SM3_256()
  Called By:
  Input:
  Output:
  Return:           0: success
                    1: paremeter initialization error
                    2: a point at infinity
                    5: X or Y coordinate is beyond Fq
                    3: not a valid point on curve
                    4: not a point of order n
                    B: public key error
                    8: the signed R out of range [1,n-1]
                    9: the signed S out of range [1,n-1]
                    A: the intermediate data t equals 0
                    C: verification fail
  Others:
****************************************************************/
int SM2_SelfCheck();

/******************************************************************************
  Function:          SM3_SelfTest
  Description:       test whether the SM3 calculation is correct by comparing
                     the hash result with the standard result
  Calls:             SM3_256
  Called By:
  Input:             null
  Output:            null
  Return:            0      //the SM3 operation is correct
                     1      //the sm3 operation is wrong
  Others:
*******************************************************************************/

/************************************************************
  Function:         SM4_SelfCheck
  Description:      Self-check with standard data
  Calls:            SM4_Encrypt, SM4_Decrypt;
  Called By:
  Input:
  Output:
  Return:           1 fail ; 0 success
  Others:
************************************************************/