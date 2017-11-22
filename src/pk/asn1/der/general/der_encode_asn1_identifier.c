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
  @file der_set_asn1_identifier.c
  ASN.1 DER, set the Identifier for encoding
*/

#ifdef LTC_DER
/**
  Encode the ASN.1 Identifier
  @param list  banana
  @param class banana
  @param pc    banana
  @param tag   banana
  @return CRYPT_OK if successful
*/

int der_encode_asn1_identifier(ltc_asn1_list *list, unsigned char *id, unsigned long *idlen)
{
   ulong64 tmp;
   unsigned long tag_len;

   LTC_ARGCHK(list  != NULL);
   LTC_ARGCHK(idlen != NULL);

   if (list->type != LTC_ASN1_CUSTOM_TYPE) {
      if (list->type >= der_asn1_type_to_identifier_map_sz) {
         return CRYPT_INVALID_ARG;
      }
      if (der_asn1_type_to_identifier_map[list->type] == -1) {
         return CRYPT_INVALID_ARG;
      }
      if (id != NULL) {
         *id = der_asn1_type_to_identifier_map[list->type];
      }
      *idlen = 1;
      return CRYPT_OK;
   } else {
      if (list->class < LTC_ASN1_CL_UNIVERSAL || list->class > LTC_ASN1_CL_PRIVATE) {
         return CRYPT_INVALID_ARG;
      }
      if (list->pc < LTC_ASN1_PC_PRIMITIVE || list->pc > LTC_ASN1_PC_CONSTRUCTED) {
         return CRYPT_INVALID_ARG;
      }
      if (list->tag > (ULONG_MAX >> (8 + 7))) {
         return CRYPT_INVALID_ARG;
      }
   }

   if (id != NULL) {
      if (*idlen < 1) {
         return CRYPT_BUFFER_OVERFLOW;
      }

      id[0] = list->class << 6 | list->pc << 5;
   }

   if (list->tag < 0x1f) {
      if (id != NULL) {
         id[0] |= list->tag & 0x1f;
      }
      *idlen = 1;
   } else {
      tag_len = 0;
      tmp = list->tag;
      do {
         tag_len++;
         tmp >>= 7;
      } while (tmp);

      if (id != NULL) {
         if (*idlen < tag_len + 1) {
            return CRYPT_BUFFER_OVERFLOW;
         }
         id[0] |= 0x1f;
         for (tmp = 1; tmp <= tag_len; ++tmp) {
            id[tmp] = ((list->tag >> (7 * (tag_len - tmp))) & 0x7f) | 0x80;
         }
         id[tag_len] &= ~0x80;
      }
      *idlen = tag_len + 1;
   }

   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
