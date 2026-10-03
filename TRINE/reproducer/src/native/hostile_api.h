#ifndef HOSTILE_API_H
#define HOSTILE_API_H

#include <stdint.h>
#include "params.h"

int hostile_derive_round_commitment_vartime(
    Fq *out_a,
    Fq *out_psi,
    const Fq *base_form,
    const uint8_t round_seed[TRINE_round_seed_bytes],
    uint32_t round_index);

#endif
