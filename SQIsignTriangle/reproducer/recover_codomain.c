#include <stdio.h>
#include <stdlib.h>
#include <verification.h>
#include <hd.h>
#include <encoded_sizes.h>

static unsigned char *read_all(const char *path, size_t *length)
{
    FILE *file = fopen(path, "rb");
    if (!file) {
        perror(path);
        exit(2);
    }
    if (fseek(file, 0, SEEK_END) ||
        (*length = (size_t)ftell(file), fseek(file, 0, SEEK_SET))) {
        perror("seek");
        exit(2);
    }
    unsigned char *data = malloc(*length ? *length : 1);
    if (!data || fread(data, 1, *length, file) != *length) {
        perror("read");
        exit(2);
    }
    fclose(file);
    return data;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s public-key signature target-message\n", argv[0]);
        return 2;
    }

    size_t pk_length, sig_length, target_length;
    unsigned char *pk_bytes = read_all(argv[1], &pk_length);
    unsigned char *sig_bytes = read_all(argv[2], &sig_length);
    unsigned char *target = read_all(argv[3], &target_length);
    if (pk_length != PUBLICKEY_BYTES || sig_length != NEW_SIGNATURE_BYTES) {
        fprintf(stderr, "unexpected lengths: pk=%zu sig=%zu\n", pk_length, sig_length);
        return 2;
    }

    public_key_t pk = {0};
    new_signature_t sig;
    public_key_from_bytes(&pk, pk_bytes);
    new_signature_from_bytes(&sig, sig_bytes);

    ibz_t q, c1, c2, c3, c4;
    ibz_init(&q);
    ibz_init(&c1);
    ibz_init(&c2);
    ibz_init(&c3);
    ibz_init(&c4);
    ibz_copy_digit_array(&q, sig.q);
    int e = ibz_bitsize(&q);
    if (e < 3 || e > TORSION_EVEN_POWER || !ibz_is_odd(&q)) {
        fprintf(stderr, "invalid q\n");
        return 3;
    }

    ec_curve_t E_pk, E_aux;
    copy_curve(&E_pk, &pk.curve);
    if (!ec_curve_init_from_A(&E_aux, &sig.E_aux_A)) {
        fprintf(stderr, "invalid auxiliary curve\n");
        return 3;
    }

    fp2_t pk_j;
    ec_j_inv(&pk_j, &pk.curve);
    ec_basis_t B_pk;
    if (!ec_curve_to_basis_2f_from_hint(
            &B_pk, &E_pk, TORSION_EVEN_POWER, pk.hint_pk)) {
        fprintf(stderr, "invalid public basis\n");
        return 3;
    }
    ec_mul(&B_pk.P, sig.q, e, &B_pk.P, &E_pk);
    ec_mul(&B_pk.Q, sig.q, e, &B_pk.Q, &E_pk);
    ec_mul(&B_pk.PmQ, sig.q, e, &B_pk.PmQ, &E_pk);
    ec_dbl_iter_basis(&B_pk, TORSION_EVEN_POWER - e, &B_pk, &E_pk);
    if (!test_basis_order_twof(&B_pk, &E_pk, e) ||
        !test_basis_order_twof(&sig.B_aux, &E_aux, e)) {
        fprintf(stderr, "invalid basis order\n");
        return 3;
    }

    theta_couple_curve_t domain, codomain;
    copy_curve(&domain.E1, &E_pk);
    copy_curve(&domain.E2, &E_aux);
    ec_curve_init(&codomain.E1);
    ec_curve_init(&codomain.E2);
    theta_kernel_couple_points_t kernel;
    copy_bases_to_kernel(&kernel, &B_pk, &sig.B_aux);
    if (!theta_chain_compute_and_eval_verify(
            e, &domain, &kernel, 0, &codomain, NULL, 0)) {
        fprintf(stderr, "isogeny chain failed\n");
        return 3;
    }

    hash_to_challenge_prime_with_pk_j(
        &c1, &c2, &pk_j, &codomain.E1, target, target_length);
    hash_to_challenge_prime_with_pk_j(
        &c3, &c4, &pk_j, &codomain.E2, target, target_length);
    printf("e=%d\n", e);
    gmp_printf("q=%Zd\ntarget1_c1=%Zd\ntarget1_c2=%Zd\n"
               "target2_c1=%Zd\ntarget2_c2=%Zd\n",
               q, c1, c2, c3, c4);
    return 0;
}
