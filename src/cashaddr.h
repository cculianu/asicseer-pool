/* Cash Address decode for ckpool.
 * Code adapted to C from C++ by Calin Culianu <calin.culianu@gmail.com>
 * LICENSE: MIT
 * Original C++ sources: Bitcoin Cash Node https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node
 */
#ifndef CASHADDR_H
#define CASHADDR_H

#include <stdint.h>

/* Returns a 20-byte buffer containing the hash160 of the pk or script decoded
 * from a cashaddr string, or NULL on bad address string. The passed-in string
 * may be preceded by a prefix such as "bitcoincash:" or "bchtest:". If no prefix
 * is specified, "bitcoincash:" is assumed. Use the correct prefix to ensure
 * proper checksum validation.
 *
 * The returned buffer must be freed by the caller.
 */
extern uint8_t *cashaddr_decode_hash160(const char *addr);

#define CASHADDR_HEURISTIC_LEN 35

#endif
