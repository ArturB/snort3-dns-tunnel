#!/usr/bin/node

var domain = process.argv[2];
if (!domain){
	console.log('Domain not specified.')
}
if (domain[0]!='.')
	domain='.'+domain;

dgram = require('dgram');
srv = dgram.createSocket('udp4')
srv.on('message',(d,r)=>{
		d[2]=0x81
		d[3]=0x80
		srv.send(d,0,d.length,r.port,r.address,(e,b)=>{});
		var dec = decode(d).q[0];
		if (dec.type == 1 && dec.name.slice(-domain.length)==domain){
			process.stdout.write((new Buffer(dec.name.slice(0,-domain.length), 'hex')).toString('ascii'))
		}
	});
srv.bind(53);

function decode(pkt){
	var skeleton = {
		id:pkt.slice(0,2).readUInt16BE(),
		flags:pkt.slice(2,4),
		questions:pkt.slice(4,6).readUInt16BE(),
		answer:pkt.slice(6,8).readUInt16BE(),
		authority:pkt.slice(8,10).readUInt16BE(),
		additional:pkt.slice(10,12).readUInt16BE(),
		q:[],
		raw:pkt,
		rawsize:pkt.length
	};
	var cursor = 12;
	for (var i = 0 ; i < skeleton.questions ; ++i){
		var qlen, name = [];
		while(qlen = pkt.slice(cursor,++cursor).readUInt8()){
			name.push(pkt.slice(cursor,cursor+qlen));
			cursor += qlen;
		}
		var q = {
			name:name.join('.'),
			type:pkt.slice(cursor,cursor+2).readUInt16BE(),
			class:pkt.slice(cursor+2,cursor+4).readUInt16BE()
		};
		skeleton.q.push(q);
		cursor+=5;
	}
	return skeleton;
}
