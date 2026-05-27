/**
 * Dragon Legion — PBKDF2-HMAC-SHA256 GPU Accelerated Cracker (Module 8.1).
 *
 * CUDA kernel for parallel PBKDF2-HMAC-SHA256 computation.
 * Used for Android FDE brute-force and iOS keychain passcode cracking.
 *
 * Compile: nvcc -O3 -arch=sm_75 -shared -Xcompiler -fPIC -o pbkdf2_cracker.so pbkdf2_cracker.cu
 */

#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32
#define THREADS_PER_BLOCK 256
#define MAX_PASSWORD_LEN 32
#define PBKDF2_BLOCKS 4096  // Default iteration count

// ---------------------------------------------------------------------------
// SHA-256 constants
// ---------------------------------------------------------------------------
__constant__ uint32_t d_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed2,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

// ---------------------------------------------------------------------------
// SHA-256 device functions
// ---------------------------------------------------------------------------
__device__ uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

__device__ void sha256_transform(uint32_t state[8], const uint8_t block[SHA256_BLOCK_SIZE]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;

    // Prepare message schedule
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + d_K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__device__ void hmac_sha256(const uint8_t *key, int key_len,
                             const uint8_t *data, int data_len,
                             uint8_t digest[SHA256_DIGEST_SIZE]) {
    uint8_t ipad[SHA256_BLOCK_SIZE];
    uint8_t opad[SHA256_BLOCK_SIZE];
    uint32_t state[8];

    // Prepare padded key
    if (key_len > SHA256_BLOCK_SIZE) {
        // Hash key first if too long (not needed for PBKDF2 use case)
        key_len = SHA256_DIGEST_SIZE;
    }

    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        ipad[i] = (i < key_len ? key[i] : 0x00) ^ 0x36;
        opad[i] = (i < key_len ? key[i] : 0x00) ^ 0x5C;
    }

    // Inner hash: SHA256(ipad || data)
    state[0] = 0x6a09e667; state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
    state[4] = 0x510e527f; state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;

    uint8_t inner_block[SHA256_BLOCK_SIZE];
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        inner_block[i] = ipad[i];
        if (i + SHA256_BLOCK_SIZE < SHA256_BLOCK_SIZE + data_len) continue;
    }
    // Simplified single-block inner hash
    sha256_transform(state, ipad);

    // Second block: data
    uint8_t data_block[SHA256_BLOCK_SIZE] = {0};
    for (int i = 0; i < data_len && i < SHA256_BLOCK_SIZE; i++) {
        data_block[i] = data[i];
    }
    // Pad data_block for SHA-256 (simplified for inline use)
    data_block[data_len] = 0x80;
    uint64_t bit_len = (uint64_t)(SHA256_BLOCK_SIZE + data_len) * 8;
    data_block[56] = (bit_len >> 56) & 0xFF;
    data_block[57] = (bit_len >> 48) & 0xFF;
    data_block[58] = (bit_len >> 40) & 0xFF;
    data_block[59] = (bit_len >> 32) & 0xFF;
    data_block[60] = (bit_len >> 24) & 0xFF;
    data_block[61] = (bit_len >> 16) & 0xFF;
    data_block[62] = (bit_len >> 8) & 0xFF;
    data_block[63] = bit_len & 0xFF;
    sha256_transform(state, data_block);

    // Store inner digest
    uint8_t inner_digest[32];
    for (int i = 0; i < 8; i++) {
        inner_digest[i * 4]     = (state[i] >> 24) & 0xFF;
        inner_digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        inner_digest[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        inner_digest[i * 4 + 3] = state[i] & 0xFF;
    }

    // Outer hash: SHA256(opad || inner_digest)
    state[0] = 0x6a09e667; state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
    state[4] = 0x510e527f; state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;

    sha256_transform(state, opad);

    uint8_t outer_block[SHA256_BLOCK_SIZE] = {0};
    for (int i = 0; i < 32; i++) outer_block[i] = inner_digest[i];
    outer_block[32] = 0x80;
    bit_len = (uint64_t)(SHA256_BLOCK_SIZE + 32) * 8;
    outer_block[56] = (bit_len >> 56) & 0xFF;
    outer_block[57] = (bit_len >> 48) & 0xFF;
    outer_block[58] = (bit_len >> 40) & 0xFF;
    outer_block[59] = (bit_len >> 32) & 0xFF;
    outer_block[60] = (bit_len >> 24) & 0xFF;
    outer_block[61] = (bit_len >> 16) & 0xFF;
    outer_block[62] = (bit_len >> 8) & 0xFF;
    outer_block[63] = bit_len & 0xFF;
    sha256_transform(state, outer_block);

    for (int i = 0; i < 8; i++) {
        digest[i * 4]     = (state[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = state[i] & 0xFF;
    }
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA256 GPU Kernel
// ---------------------------------------------------------------------------

/**
 * Compute PBKDF2-HMAC-SHA256 for one password candidate.
 *
 * Each thread processes one password, computing 4096 iterations of HMAC-SHA256.
 * Results are written to d_results (32 bytes per thread).
 *
 * @param d_passwords     Flat array of password strings (MAX_PASSWORD_LEN bytes each)
 * @param d_salt          Salt (32 bytes, shared by all threads)
 * @param num_iterations  Number of PBKDF2 iterations
 * @param d_results       32-byte derived keys output
 */
__global__ void pbkdf2_hmac_sha256_kernel(
    const uint8_t *d_passwords,
    const uint8_t *d_salt,
    int num_iterations,
    uint8_t *d_results
) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    const uint8_t *password = d_passwords + tid * MAX_PASSWORD_LEN;

    // Password length (find null terminator or max)
    int pass_len = 0;
    for (int i = 0; i < MAX_PASSWORD_LEN; i++) {
        if (password[i] == 0) break;
        pass_len++;
    }

    // Prepare salt + block index (i = 1 for single-block PBKDF2)
    uint8_t salt_block[64];
    int salt_len = 32;  // Assume 32-byte salt
    for (int i = 0; i < salt_len; i++) {
        salt_block[i] = d_salt[i];
    }
    salt_block[salt_len]     = 0x00;  // Block index = 1
    salt_block[salt_len + 1] = 0x00;
    salt_block[salt_len + 2] = 0x00;
    salt_block[salt_len + 3] = 0x01;

    uint8_t U[32], T[32] = {0};

    // First iteration: U1 = HMAC-SHA256(password, salt || 0x00000001)
    hmac_sha256(password, pass_len, salt_block, salt_len + 4, U);
    for (int i = 0; i < 32; i++) T[i] = U[i];

    // Remaining iterations: U_i = HMAC-SHA256(password, U_{i-1}), T ^= U_i
    for (int iter = 1; iter < num_iterations; iter++) {
        hmac_sha256(password, pass_len, U, 32, U);
        for (int i = 0; i < 32; i++) T[i] ^= U[i];
    }

    // Store result
    for (int i = 0; i < 32; i++) {
        d_results[tid * 32 + i] = T[i];
    }
}

// ---------------------------------------------------------------------------
// Host-side C interface (for ctypes)
// ---------------------------------------------------------------------------

extern "C" {

/**
 * Launch PBKDF2 kernel for multiple password candidates.
 *
 * @param passwords     Flat password array (max_len bytes per candidate)
 * @param num_passwords Number of password candidates
 * @param salt          32-byte salt
 * @param iterations    PBKDF2 iteration count
 * @param results_out   32 * num_passwords bytes output buffer (pre-allocated on host)
 * @return 0 on success, -1 on error
 */
int crack_pbkdf2_gpu(
    const uint8_t *passwords,
    int num_passwords,
    const uint8_t *salt,
    int iterations,
    uint8_t *results_out
) {
    size_t pass_size = num_passwords * MAX_PASSWORD_LEN;
    size_t result_size = num_passwords * 32;

    uint8_t *d_passwords, *d_salt, *d_results;
    cudaError_t err;

    // Allocate device memory
    err = cudaMalloc(&d_passwords, pass_size);
    if (err != cudaSuccess) { fprintf(stderr, "cudaMalloc failed: %s\n", cudaGetErrorString(err)); return -1; }

    err = cudaMalloc(&d_salt, 32);
    if (err != cudaSuccess) { cudaFree(d_passwords); return -1; }

    err = cudaMalloc(&d_results, result_size);
    if (err != cudaSuccess) { cudaFree(d_passwords); cudaFree(d_salt); return -1; }

    // Copy inputs to device
    cudaMemcpy(d_passwords, passwords, pass_size, cudaMemcpyHostToDevice);
    cudaMemcpy(d_salt, salt, 32, cudaMemcpyHostToDevice);

    // Launch kernel
    int blocks = (num_passwords + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK;
    pbkdf2_hmac_sha256_kernel<<<blocks, THREADS_PER_BLOCK>>>(
        d_passwords, d_salt, iterations, d_results
    );

    err = cudaGetLastError();
    if (err != cudaSuccess) {
        fprintf(stderr, "Kernel launch failed: %s\n", cudaGetErrorString(err));
        cudaFree(d_passwords); cudaFree(d_salt); cudaFree(d_results);
        return -1;
    }

    cudaDeviceSynchronize();

    // Copy results back
    cudaMemcpy(results_out, d_results, result_size, cudaMemcpyDeviceToHost);

    cudaFree(d_passwords);
    cudaFree(d_salt);
    cudaFree(d_results);

    return 0;
}

}  // extern "C"
