
/* Reproducer-only adapter appended to a temporary copy of the submitted
 * SIG_AlgorithmInstance.c.  It preserves the submitted key-generation path
 * but retains the decoded objects needed by the local signing oracle. */
int uvw_reproducer_keygen(uvw_secret_key *out_sk, uvw_public_key *out_pk)
{
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned char *pk = malloc(pk_len);
    unsigned char *sk = malloc(sk_len);
    if (!pk || !sk) {
        free(pk);
        free(sk);
        return -1;
    }
    if (sig_keygen(pk, &pk_len, sk, &sk_len)) {
        free(pk);
        free(sk);
        return -1;
    }

    deserialize_pk(out_pk, pk);
    const uint16_t nonce_x =
        ((uint16_t)sk[SEED_LEN_BYTES] << 8) | sk[SEED_LEN_BYTES + 1];
    const uint16_t nonce_y =
        ((uint16_t)sk[SEED_LEN_BYTES + 2] << 8) | sk[SEED_LEN_BYTES + 3];
    const uint16_t nonce_z =
        ((uint16_t)sk[SEED_LEN_BYTES + 4] << 8) | sk[SEED_LEN_BYTES + 5];
    const uint16_t nonce_d =
        ((uint16_t)sk[SEED_LEN_BYTES + 6] << 8) | sk[SEED_LEN_BYTES + 7];
    rebuild_for_sign(uvw_param_from_level(1), sk, nonce_x, nonce_y, nonce_z,
                     nonce_d, out_sk);
    free(pk);
    free(sk);
    return 0;
}
