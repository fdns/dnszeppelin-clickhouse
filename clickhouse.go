package main

import (
	"database/sql/driver"
	"fmt"
	"github.com/kshvakov/clickhouse"
	"log"
	"time"
)

func connectClickhouseRetry(exiting chan bool, clickhouseHost string) clickhouse.Clickhouse {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		c, err := connectClickhouse(exiting, clickhouseHost)
		if err == nil {
			return c
		}

		// Error getting connection, wait the timer or check if we are exiting
		select {
		case <-exiting:
			// When exiting, return immediately
			return nil
		case <-tick.C:
			continue
		}
	}
}

func connectClickhouse(exiting chan bool, clickhouseHost string) (clickhouse.Clickhouse, error) {
	connection, err := clickhouse.OpenDirect(fmt.Sprintf("tcp://%v?debug=false", clickhouseHost))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	{
		stmt, _ := connection.Prepare(`
	CREATE TABLE IF NOT EXISTS DNS_LOG (
		DnsDate Date,
		timestamp DateTime,
		Server String,
		IPVersion UInt8,
		IPPrefix UInt32,
		Protocol FixedString(3),
		QR UInt8,
		OpCode UInt8,
		Class UInt16,
		Type UInt16,
		Edns0Present UInt8,
		DoBit UInt8,
		ResponceCode UInt8,
		Question String,
		Size UInt16
	) engine=MergeTree(DnsDate, (timestamp, Server), 8192)
	`)
		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to fetch the top queried domains
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_DOMAIN_COUNT
		ENGINE=SummingMergeTree(DnsDate, (t, Server, Question), 8192, c) AS
		SELECT DnsDate, toStartOfMinute(timestamp) as t, Server, Question, count(*) as c FROM DNS_LOG WHERE QR=0 GROUP BY DnsDate, t, Server, Question
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to fetch the unique domain count
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_DOMAIN_UNIQUE
		ENGINE=AggregatingMergeTree(DnsDate, (timestamp, Server), 8192) AS
		SELECT DnsDate, timestamp, Server, uniqState(Question) AS UniqueDnsCount FROM DNS_LOG WHERE QR=0 GROUP BY Server, DnsDate, timestamp
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to fetch the querys by protocol
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_PROTOCOL
		ENGINE=SummingMergeTree(DnsDate, (timestamp, Server, Protocol), 8192, (c)) AS
		SELECT DnsDate, timestamp, Server, Protocol, count(*) as c FROM DNS_LOG GROUP BY Server, DnsDate, timestamp, Protocol
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to aggregate the general packet information
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_GENERAL_AGGREGATIONS
		ENGINE=AggregatingMergeTree(DnsDate, (timestamp, Server), 8192) AS
		SELECT DnsDate, timestamp, Server, sumState(Size) AS TotalSize, avgState(Size) AS AverageSize, sumState(Edns0Present) as EdnsCount, sumState(DoBit) as DoBitCount FROM DNS_LOG GROUP BY Server, DnsDate, timestamp
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to aggregate the edns information
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_EDNS
		ENGINE=AggregatingMergeTree(DnsDate, (timestamp, Server), 8192) AS
		SELECT DnsDate, timestamp, Server, sumState(Edns0Present) as EdnsCount, sumState(DoBit) as DoBitCount FROM DNS_LOG WHERE QR=0 GROUP BY Server, DnsDate, timestamp
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to fetch the querys by OpCode
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_OPCODE
		ENGINE=SummingMergeTree(DnsDate, (timestamp, Server, OpCode), 8192, c) AS
		SELECT DnsDate, timestamp, Server, OpCode, count(*) as c FROM DNS_LOG WHERE QR=0 GROUP BY Server, DnsDate, timestamp, OpCode
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to fetch the querys by Query Type
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_TYPE
		ENGINE=SummingMergeTree(DnsDate, (timestamp, Server, Type), 8192, c) AS
		SELECT DnsDate, timestamp, Server, Type, count(*) as c FROM DNS_LOG WHERE QR=0 GROUP BY Server, DnsDate, timestamp, Type
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to fetch the querys by Query Class
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_CLASS
		ENGINE=SummingMergeTree(DnsDate, (timestamp, Server, Class), 8192, c) AS
		SELECT DnsDate, timestamp, Server, Class, count(*) as c FROM DNS_LOG WHERE QR=0 GROUP BY Server, DnsDate, timestamp, Class
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to fetch the querys by Responce
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_RESPONCECODE
		ENGINE=SummingMergeTree(DnsDate, (timestamp, Server, ResponceCode), 8192, c) AS
		SELECT DnsDate, timestamp, Server, ResponceCode, count(*) as c FROM DNS_LOG WHERE QR=1 GROUP BY Server, DnsDate, timestamp, ResponceCode
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to fetch the queries by IP Prefix
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_IP_MASK
		ENGINE=SummingMergeTree(DnsDate, (timestamp, Server, IPVersion, IPPrefix), 8192, c) AS
		SELECT DnsDate, timestamp, Server, IPVersion, IPPrefix, count(*) as c FROM DNS_LOG GROUP BY Server, DnsDate, timestamp, IPVersion, IPPrefix
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	return connection, nil
}
