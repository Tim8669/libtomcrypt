/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt.h"

/**
  @file der_length_asn1_identifier.c
  ASN.1 DER, set the Identifier for encoding
*/

#ifdef LTC_DER
/**
  Get the length when encoding the ASN.1 Identifier
  @param list  banana
  @param idlen banana
  @return CRYPT_OK if successful
*/

int der_length_asn1_identifier(ltc_asn1_list *list, unsigned long *idlen)
{
   return der_encode_asn1_identifier(list, NULL, idlen);
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
