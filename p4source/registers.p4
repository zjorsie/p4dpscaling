register usage_info {
	width: 48;
	instance_count: HASH_SIZE;
}

register packet_stats {
	width: 32;
	instance_count:HASH_SIZE;
}

register _mig_proxyStateless {
	width: 64;
	instance_count: HASH_SIZE;
}
register flowUpdateCounter {
	width: 8;
	instance_count: HASH_SIZE;
}
register flowNums {
	width: 32;
	instance_count: HASH_SIZE;
}
// registers with 14 bit keys and 8 bit values
register flowTable {
	width: 8;
	instance_count: HASH_SIZE;
}

register flowSession {
	width: 8;
	instance_count: HASH_SIZE;
}
register flowSequence {
	width: 8;
	instance_count: HASH_SIZE;
}

register flowReceiveID {
	width: 16;
	instance_count:HASH_SIZE;
}
register flowVNFID {
	width: 8;
	instance_count: HASH_SIZE;
}

register reg_packetCounter {
	width: 32;
	instance_count: HASH_SIZE;
}