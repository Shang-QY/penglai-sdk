/************************************************************************
  Copyright (c) IPADS@SJTU 2021. Modification to support Penglai (RISC-V TEE)
  
  This file contains implementation of SM4 algorithm, part of
  codes provided by the Commercial Cryptography Testing Center,
  see <http://www.scctc.org.cn> for more infomation.

  Function List:
    1. SM4_KeySchedule             //Generate the required round keys
    2. SM4_Encrypt                 //Encryption function
    3. SM4_Decrypt                 //Decryption function
    4. SM4_SelfCheck               //Self-check
**************************************************************************/

#pragma once

//rotate n bits to the left in a 32bit buffer
#define SM4_Rotl32(buf, n) (((buf) << n) | ((buf) >> (32 - n)))

/************************************************************
  Function:         SM4_KeySchedule
  Description:      Generate round keys
  Calls:
  Called By:        SM4_Encrypt, SM4_Decrypt;
  Input:            MK[]: Master key
  Output:           rk[]: round keys
  Return:null
  Others:
************************************************************/
void SM4_KeySchedule(const unsigned char MK[], unsigned int rk[]);

/************************************************************
  Function:SM4_Encrypt(unsigned char MK[], unsigned char PlainText[], unsigned char CipherText[]);
  Description:      Encryption function
  Calls:            SM4_KeySchedule
  Called By:
  Input:            MK[]: Master key
                    PlainText[]: input text
  Output:           CipherText[]: output text
  Return:null
  Others:
************************************************************/
void SM4_Encrypt(const unsigned char MK[], unsigned char PlainText[], unsigned char CipherText[]);

/************************************************************
  Function:         SM4_Decrypt
  Description:      Decryption function
  Calls:            SM4_KeySchedule
  Called By:
  Input:            MK[]: Master key
                    CipherText[]: input text
  Output:           PlainText[]: output text
  Return:           null
  Others:
************************************************************/
void SM4_Decrypt(const unsigned char MK[], unsigned char CipherText[], unsigned char PlainText[]);

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
int SM4_SelfCheck();
