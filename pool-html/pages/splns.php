<p><b>Features of SPLNS</b></p>

<ul>
<li><b>Hop proof</b>: Miners cannot game SPLNS by pool hopping.</li>
<li><b>Share score</b>: Shares are scored by the difficulty of the share found.</li>
<li><b>Provably fair</b>: The blockchain contains a record of all pool earnings and distributions.</li>
<li><b>Block finder reward</b>:  Found blocks are scored heavily, but the reward is distributed to the next found block.</li>
<li><b>Shorter ramp-up time</b>: Compared to PPLNS, rewards rise to stable levels more rapidly when miners first start hashing.</li>
<li><b>Longer ramp-down time</b>: Minimizes intermittent miner variance. Rewards continue to be distributed after mining stops.</li>
<li><b>Malicious and faulty miner penalties</b>: Miners that withhold blocks earn fewer rewards.</li>
<li><b>On-the-fly score</b>: <code>share_score = sqrt(MIN(share_diff, network_diff) / work_diff) * work_diff / 2</code></li>
<li><b>On-the-fly reward</b>: <code>share_reward = miner_share_diff/pool_share_diff</code></li>
</ul>
