/*
 * Copyright (c) 2020 Calin Culianu <calin.culianu@gmail.com>
 * Copyright (c) 2020 ASICseer https://asicseer.com
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */
#ifndef DONATION_H
#define DONATION_H

/* Some constants related to auto-donation. Donations go as the 2nd and 3rd
   outputs of the coinbase generation tx, and are subtracted from pool fee. */

#define DONATION_FRACTION 10 // 10% of pool_fee per address below (set to 0 if you wish to disable donation)

#define DONATION_ADDRESS_CALIN "1Ca1inCimwRhhcpFX84TPRrPQSryTgKW6N" // Calin (dev)
#define DONATION_ADDRESS_BCHN "3NoBpEBHZq6YqwUBdPAMW41w5BTJSC7yuQ"  // BCHN donation wallet
#define DONATION_NUM_ADDRESSES 2

#endif
