-- SQLite

--INSERT INTO VNF (service, srcIP, dstIP, srcPort, dstPort, prio) VALUES ('test1', '10.0.1.2', '10.0.1.20', '500', '500', 1);

--INSERT INTO VNF (service, srcIP, dstIP, srcPort, dstPort, prio) VALUES ('test2', '10.0.1.2', '10.0.1.20', '500', '500', -100);
--INSERT INTO VNF (service, srcIP, dstIP, srcPort, dstPort, prio) VALUES ('test2', '10.0.1.2', '10.0.1.20', '500', '500', -5);

select * from VNF where srcIP IN ('ALL', '10.0.1.10');

