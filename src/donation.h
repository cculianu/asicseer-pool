#ifndef DONATION_H
#define DONATION_H

/* Some constants related to auto-donation */

// NOTE: Currently in SPLNS donations are disabled, so the below has no effect

// Note even though this codebase supports cashaddr, for now the below two addresses should be in
// legacy format (base58 encoded), otherwise behavior is undefined. Sorry!
#define DONATION_P2PKH "1Ca1inCimwRhhcpFX84TPRrPQSryTgKW6N" // Calin (dev)
#define DONATION_P2SH "3NoBpEBHZq6YqwUBdPAMW41w5BTJSC7yuQ"  // BCHN donation wallet

#define DONATION_FRACTION 200 // 0.5% (set to 0 if you wish to disable donation)


#endif
