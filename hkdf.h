#ifndef _HKDF_H_
#define _HKDF_H_

#include <stdint.h>
#include <stddef.h>

void hmac_hash(uint8_t finalresult[32],
               const void *initial_salt, size_t initial_salt_len,
               const void *material, size_t material_len);

void hkdf_extract(uint8_t result[32],
                  const void *initial_salt, size_t initial_salt_len,
                  const void *material, size_t material_len);

void hkdf_expand(void *result, uint16_t result_len,
                 const void *info, uint16_t info_len,
                 const uint8_t prk[32]);

void hkdf_form_label(char hkdf_label[520], uint16_t *hkdf_label_len,
                     const void *label, uint8_t label_len,
                     const void *context, uint8_t context_len,
		     uint16_t result_len);

void hkdf_expand_label(void *result, uint16_t result_len,
                       const void *label, uint8_t label_len,
                       const void *context, uint8_t context_len,
                       const uint8_t prk[32]);
void hkdf_expand_label_precalc(void *result, uint16_t result_len,
                               const char hkdf_label[520], uint16_t hkdf_label_len,
                               const uint8_t prk[32]);

#endif
