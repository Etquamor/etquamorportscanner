__author__ = "Etquamor"
__date__ = "31.01.2019"

def createDatabase():
    ports = """0 	tcp 		Reserved
0 	udp 		Reserved
1 	tcp 	tcpmux 	TCP Port Service Multiplexer
1 	udp 	tcpmux 	TCP Port Service Multiplexer
2 	tcp 	compressnet 	Management Utility
2 	udp 	compressnet 	Management Utility
3 	tcp 	compressnet 	Compression Process
3 	udp 	compressnet 	Compression Process
4 	tcp 		Unassigned
4 	udp 		Unassigned
5 	tcp 	rje 	Remote Job Entry
5 	udp 	rje 	Remote Job Entry
6 	tcp 		Unassigned
6 	udp 		Unassigned
7 	tcp 	echo 	Echo
7 	udp 	echo 	Echo
8 	tcp 		Unassigned
8 	udp 		Unassigned
9 	tcp 	discard 	Discard
9 	udp 	discard 	Discard
9 	sctp 	discard 	Discard
9 	dccp 	discard 	Discard
10 	tcp 		Unassigned
10 	udp 		Unassigned
11 	tcp 	systat 	Active Users
11 	udp 	systat 	Active Users
12 	tcp 		Unassigned
12 	udp 		Unassigned
13 	tcp 	daytime 	Daytime
13 	udp 	daytime 	Daytime
14 	tcp 		Unassigned
14 	udp 		Unassigned
15 	tcp 		Unassigned [was netstat]
15 	udp 		Unassigned
16 	tcp 		Unassigned
16 	udp 		Unassigned
17 	tcp 	qotd 	Quote of the Day
17 	udp 	qotd 	Quote of the Day
18 	tcp 	msp 	Message Send Protocol (historic)
18 	udp 	msp 	Message Send Protocol (historic)
19 	tcp 	chargen 	Character Generator
19 	udp 	chargen 	Character Generator
20 	tcp 	ftp-data 	File Transfer [Default Data]
20 	udp 	ftp-data 	File Transfer [Default Data]
20 	sctp 	ftp-data 	FTP
21 	tcp 	ftp 	File Transfer Protocol [Control]
21 	udp 	ftp 	File Transfer Protocol [Control]
21 	sctp 	ftp 	FTP
22 	tcp 	ssh 	The Secure Shell (SSH) Protocol
22 	udp 	ssh 	The Secure Shell (SSH) Protocol
22 	sctp 	ssh 	SSH
23 	tcp 	telnet 	Telnet
23 	udp 	telnet 	Telnet
24 	tcp 		any private mail system
24 	udp 		any private mail system
25 	tcp 	smtp 	Simple Mail Transfer
25 	udp 	smtp 	Simple Mail Transfer
26 	tcp 		Unassigned
26 	udp 		Unassigned
27 	tcp 	nsw-fe 	NSW User System FE
27 	udp 	nsw-fe 	NSW User System FE
28 	tcp 		Unassigned
28 	udp 		Unassigned
29 	tcp 	msg-icp 	MSG ICP
29 	udp 	msg-icp 	MSG ICP
30 	tcp 		Unassigned
30 	udp 		Unassigned
31 	tcp 	msg-auth 	MSG Authentication
31 	udp 	msg-auth 	MSG Authentication
32 	tcp 		Unassigned
32 	udp 		Unassigned
33 	tcp 	dsp 	Display Support Protocol
33 	udp 	dsp 	Display Support Protocol
34 	tcp 		Unassigned
34 	udp 		Unassigned
35 	tcp 		any private printer server
35 	udp 		any private printer server
36 	tcp 		Unassigned
36 	udp 		Unassigned
37 	tcp 	time 	Time
37 	udp 	time 	Time
38 	tcp 	rap 	Route Access Protocol
38 	udp 	rap 	Route Access Protocol
39 	tcp 	rlp 	Resource Location Protocol
39 	udp 	rlp 	Resource Location Protocol
40 	tcp 		Unassigned
40 	udp 		Unassigned
41 	tcp 	graphics 	Graphics
41 	udp 	graphics 	Graphics
42 	tcp 	name 	Host Name Server
42 	udp 	name 	Host Name Server
42 	tcp 	nameserver 	Host Name Server
42 	udp 	nameserver 	Host Name Server
43 	tcp 	nicname 	Who Is
43 	udp 	nicname 	Who Is
44 	tcp 	mpm-flags 	MPM FLAGS Protocol
44 	udp 	mpm-flags 	MPM FLAGS Protocol
45 	tcp 	mpm 	Message Processing Module [recv]
45 	udp 	mpm 	Message Processing Module [recv]
46 	tcp 	mpm-snd 	MPM [default send]
46 	udp 	mpm-snd 	MPM [default send]
47 	tcp 		Reserved
47 	udp 		Reserved
48 	tcp 	auditd 	Digital Audit Daemon
48 	udp 	auditd 	Digital Audit Daemon
49 	tcp 	tacacs 	Login Host Protocol (TACACS)
49 	udp 	tacacs 	Login Host Protocol (TACACS)
50 	tcp 	re-mail-ck 	Remote Mail Checking Protocol
50 	udp 	re-mail-ck 	Remote Mail Checking Protocol
51 			Reserved
52 	tcp 	xns-time 	XNS Time Protocol
52 	udp 	xns-time 	XNS Time Protocol
53 	tcp 	domain 	Domain Name Server
53 	udp 	domain 	Domain Name Server
54 	tcp 	xns-ch 	XNS Clearinghouse
54 	udp 	xns-ch 	XNS Clearinghouse
55 	tcp 	isi-gl 	ISI Graphics Language
55 	udp 	isi-gl 	ISI Graphics Language
56 	tcp 	xns-auth 	XNS Authentication
56 	udp 	xns-auth 	XNS Authentication
57 	tcp 		any private terminal access
57 	udp 		any private terminal access
58 	tcp 	xns-mail 	XNS Mail
58 	udp 	xns-mail 	XNS Mail
59 	tcp 		any private file service
59 	udp 		any private file service
60 	tcp 		Unassigned
60 	udp 		Unassigned
61 	tcp 		Reserved
61 	udp 		Reserved
62 	tcp 	acas 	ACA Services
62 	udp 	acas 	ACA Services
63 	tcp 	whoispp 	whois++
IANA assigned this well-formed service name as a replacement for “whois++”.
63 	tcp 	whois++ 	whois++
63 	udp 	whoispp 	whois++
IANA assigned this well-formed service name as a replacement for “whois++”.
63 	udp 	whois++ 	whois++
64 	tcp 	covia 	Communications Integrator (CI)
64 	udp 	covia 	Communications Integrator (CI)
65 	tcp 	tacacs-ds 	TACACS-Database Service
65 	udp 	tacacs-ds 	TACACS-Database Service
66 	tcp 	sql-net 	Oracle SQL*NET
IANA assigned this well-formed service name as a replacement for “sql*net”.
66 	tcp 	sql*net 	Oracle SQL*NET
66 	udp 	sql-net 	Oracle SQL*NET
IANA assigned this well-formed service name as a replacement for “sql*net”.
66 	udp 	sql*net 	Oracle SQL*NET
67 	tcp 	bootps 	Bootstrap Protocol Server
67 	udp 	bootps 	Bootstrap Protocol Server
68 	tcp 	bootpc 	Bootstrap Protocol Client
68 	udp 	bootpc 	Bootstrap Protocol Client
69 	tcp 	tftp 	Trivial File Transfer
69 	udp 	tftp 	Trivial File Transfer
70 	tcp 	gopher 	Gopher
70 	udp 	gopher 	Gopher
71 	tcp 	netrjs-1 	Remote Job Service
71 	udp 	netrjs-1 	Remote Job Service
72 	tcp 	netrjs-2 	Remote Job Service
72 	udp 	netrjs-2 	Remote Job Service
73 	tcp 	netrjs-3 	Remote Job Service
73 	udp 	netrjs-3 	Remote Job Service
74 	tcp 	netrjs-4 	Remote Job Service
74 	udp 	netrjs-4 	Remote Job Service
75 	tcp 		any private dial out service
75 	udp 		any private dial out service
76 	tcp 	deos 	Distributed External Object Store
76 	udp 	deos 	Distributed External Object Store
77 	tcp 		any private RJE service
77 	udp 		any private RJE service
78 	tcp 	vettcp 	vettcp
78 	udp 	vettcp 	vettcp
79 	tcp 	finger 	Finger
79 	udp 	finger 	Finger
80 	tcp 	http 	World Wide Web HTTP
80 	udp 	http 	World Wide Web HTTP
80 	tcp 	www 	World Wide Web HTTP
80 	udp 	www 	World Wide Web HTTP
80 	tcp 	www-http 	World Wide Web HTTP
80 	udp 	www-http 	World Wide Web HTTP
80 	sctp 	http 	HTTP
81 			Unassigned
82 	tcp 	xfer 	XFER Utility
82 	udp 	xfer 	XFER Utility
83 	tcp 	mit-ml-dev 	MIT ML Device
83 	udp 	mit-ml-dev 	MIT ML Device
84 	tcp 	ctf 	Common Trace Facility
84 	udp 	ctf 	Common Trace Facility
85 	tcp 	mit-ml-dev 	MIT ML Device
85 	udp 	mit-ml-dev 	MIT ML Device
86 	tcp 	mfcobol 	Micro Focus Cobol
86 	udp 	mfcobol 	Micro Focus Cobol
87 	tcp 		any private terminal link
87 	udp 		any private terminal link
88 	tcp 	kerberos 	Kerberos
88 	udp 	kerberos 	Kerberos
89 	tcp 	su-mit-tg 	SU/MIT Telnet Gateway
89 	udp 	su-mit-tg 	SU/MIT Telnet Gateway
90 	tcp 	dnsix 	DNSIX Securit Attribute Token Map
90 	udp 	dnsix 	DNSIX Securit Attribute Token Map
91 	tcp 	mit-dov 	MIT Dover Spooler
91 	udp 	mit-dov 	MIT Dover Spooler
92 	tcp 	npp 	Network Printing Protocol
92 	udp 	npp 	Network Printing Protocol
93 	tcp 	dcp 	Device Control Protocol
93 	udp 	dcp 	Device Control Protocol
94 	tcp 	objcall 	Tivoli Object Dispatcher
94 	udp 	objcall 	Tivoli Object Dispatcher
95 	tcp 	supdup 	SUPDUP
95 	udp 	supdup 	SUPDUP
96 	tcp 	dixie 	DIXIE Protocol Specification
96 	udp 	dixie 	DIXIE Protocol Specification
97 	tcp 	swift-rvf 	Swift Remote Virtural File Protocol
97 	udp 	swift-rvf 	Swift Remote Virtural File Protocol
98 	tcp 	tacnews 	TAC News
98 	udp 	tacnews 	TAC News
99 	tcp 	metagram 	Metagram Relay
99 	udp 	metagram 	Metagram Relay
100 			Unassigned
101 	tcp 	hostname 	NIC Host Name Server
101 	udp 	hostname 	NIC Host Name Server
102 	tcp 	iso-tsap 	ISO-TSAP Class 0
102 	udp 	iso-tsap 	ISO-TSAP Class 0
103 	tcp 	gppitnp 	Genesis Point-to-Point Trans Net
103 	udp 	gppitnp 	Genesis Point-to-Point Trans Net
104 	tcp 	acr-nema 	ACR-NEMA Digital Imag. & Comm. 300
104 	udp 	acr-nema 	ACR-NEMA Digital Imag. & Comm. 300
105 	tcp 	cso 	CCSO name server protocol
105 	udp 	cso 	CCSO name server protocol
105 	tcp 	csnet-ns 	Mailbox Name Nameserver
105 	udp 	csnet-ns 	Mailbox Name Nameserver
106 	tcp 	3com-tsmux 	3COM-TSMUX
106 	udp 	3com-tsmux 	3COM-TSMUX
107 	tcp 	rtelnet 	Remote Telnet Service
107 	udp 	rtelnet 	Remote Telnet Service
108 	tcp 	snagas 	SNA Gateway Access Server
108 	udp 	snagas 	SNA Gateway Access Server
109 	tcp 	pop2 	Post Office Protocol – Version 2
109 	udp 	pop2 	Post Office Protocol – Version 2
110 	tcp 	pop3 	Post Office Protocol – Version 3
110 	udp 	pop3 	Post Office Protocol – Version 3
111 	tcp 	sunrpc 	SUN Remote Procedure Call
111 	udp 	sunrpc 	SUN Remote Procedure Call
112 	tcp 	mcidas 	McIDAS Data Transmission Protocol
112 	udp 	mcidas 	McIDAS Data Transmission Protocol
113 	tcp 	ident 	
113 	tcp 	auth 	Authentication Service
113 	udp 	auth 	Authentication Service
114 			unassigned
115 	tcp 	sftp 	Simple File Transfer Protocol
115 	udp 	sftp 	Simple File Transfer Protocol
116 	tcp 	ansanotify 	ANSA REX Notify
116 	udp 	ansanotify 	ANSA REX Notify
117 	tcp 	uucp-path 	UUCP Path Service
117 	udp 	uucp-path 	UUCP Path Service
118 	tcp 	sqlserv 	SQL Services
118 	udp 	sqlserv 	SQL Services
119 	tcp 	nntp 	Network News Transfer Protocol
119 	udp 	nntp 	Network News Transfer Protocol
120 	tcp 	cfdptkt 	CFDPTKT
120 	udp 	cfdptkt 	CFDPTKT
121 	tcp 	erpc 	Encore Expedited Remote Pro.Call
121 	udp 	erpc 	Encore Expedited Remote Pro.Call
122 	tcp 	smakynet 	SMAKYNET
122 	udp 	smakynet 	SMAKYNET
123 	tcp 	ntp 	Network Time Protocol
123 	udp 	ntp 	Network Time Protocol
124 	tcp 	ansatrader 	ANSA REX Trader
124 	udp 	ansatrader 	ANSA REX Trader
125 	tcp 	locus-map 	Locus PC-Interface Net Map Ser
125 	udp 	locus-map 	Locus PC-Interface Net Map Ser
126 	tcp 	nxedit 	NXEdit
126 	udp 	nxedit 	NXEdit
127 	tcp 	locus-con 	Locus PC-Interface Conn Server
127 	udp 	locus-con 	Locus PC-Interface Conn Server
128 	tcp 	gss-xlicen 	GSS X License Verification
128 	udp 	gss-xlicen 	GSS X License Verification
129 	tcp 	pwdgen 	Password Generator Protocol
129 	udp 	pwdgen 	Password Generator Protocol
130 	tcp 	cisco-fna 	cisco FNATIVE
130 	udp 	cisco-fna 	cisco FNATIVE
131 	tcp 	cisco-tna 	cisco TNATIVE
131 	udp 	cisco-tna 	cisco TNATIVE
132 	tcp 	cisco-sys 	cisco SYSMAINT
132 	udp 	cisco-sys 	cisco SYSMAINT
133 	tcp 	statsrv 	Statistics Service
133 	udp 	statsrv 	Statistics Service
134 	tcp 	ingres-net 	INGRES-NET Service
134 	udp 	ingres-net 	INGRES-NET Service
135 	tcp 	epmap 	DCE endpoint resolution
135 	udp 	epmap 	DCE endpoint resolution
136 	tcp 	profile 	PROFILE Naming System
136 	udp 	profile 	PROFILE Naming System
137 	tcp 	netbios-ns 	NETBIOS Name Service
137 	udp 	netbios-ns 	NETBIOS Name Service
138 	tcp 	netbios-dgm 	NETBIOS Datagram Service
138 	udp 	netbios-dgm 	NETBIOS Datagram Service
139 	tcp 	netbios-ssn 	NETBIOS Session Service
139 	udp 	netbios-ssn 	NETBIOS Session Service
140 	tcp 	emfis-data 	EMFIS Data Service
140 	udp 	emfis-data 	EMFIS Data Service
141 	tcp 	emfis-cntl 	EMFIS Control Service
141 	udp 	emfis-cntl 	EMFIS Control Service
142 	tcp 	bl-idm 	Britton-Lee IDM
142 	udp 	bl-idm 	Britton-Lee IDM
143 	tcp 	imap 	Internet Message Access Protocol
143 	udp 	imap 	Internet Message Access Protocol
144 	tcp 	uma 	Universal Management Architecture
144 	udp 	uma 	Universal Management Architecture
145 	tcp 	uaac 	UAAC Protocol
145 	udp 	uaac 	UAAC Protocol
146 	tcp 	iso-tp0 	ISO-IP0
146 	udp 	iso-tp0 	ISO-IP0
147 	tcp 	iso-ip 	ISO-IP
147 	udp 	iso-ip 	ISO-IP
148 	tcp 	jargon 	Jargon
148 	udp 	jargon 	Jargon
149 	tcp 	aed-512 	AED 512 Emulation Service
149 	udp 	aed-512 	AED 512 Emulation Service
150 	tcp 	sql-net 	SQL-NET
150 	udp 	sql-net 	SQL-NET
151 	tcp 	hems 	HEMS
151 	udp 	hems 	HEMS
152 	tcp 	bftp 	Background File Transfer Program
152 	udp 	bftp 	Background File Transfer Program
153 	tcp 	sgmp 	SGMP
153 	udp 	sgmp 	SGMP
154 	tcp 	netsc-prod 	NETSC
154 	udp 	netsc-prod 	NETSC
155 	tcp 	netsc-dev 	NETSC
155 	udp 	netsc-dev 	NETSC
156 	tcp 	sqlsrv 	SQL Service
156 	udp 	sqlsrv 	SQL Service
157 	tcp 	knet-cmp 	KNET/VM Command/Message Protocol
157 	udp 	knet-cmp 	KNET/VM Command/Message Protocol
158 	tcp 	pcmail-srv 	PCMail Server
158 	udp 	pcmail-srv 	PCMail Server
159 	tcp 	nss-routing 	NSS-Routing
159 	udp 	nss-routing 	NSS-Routing
160 	tcp 	sgmp-traps 	SGMP-TRAPS
160 	udp 	sgmp-traps 	SGMP-TRAPS
161 	tcp 	snmp 	SNMP
161 	udp 	snmp 	SNMP
162 	tcp 	snmptrap 	SNMPTRAP
162 	udp 	snmptrap 	SNMPTRAP
163 	tcp 	cmip-man 	CMIP/TCP Manager
163 	udp 	cmip-man 	CMIP/TCP Manager
164 	tcp 	cmip-agent 	CMIP/TCP Agent
164 	udp 	cmip-agent 	CMIP/TCP Agent
165 	tcp 	xns-courier 	Xerox
165 	udp 	xns-courier 	Xerox
166 	tcp 	s-net 	Sirius Systems
166 	udp 	s-net 	Sirius Systems
167 	tcp 	namp 	NAMP
167 	udp 	namp 	NAMP
168 	tcp 	rsvd 	RSVD
168 	udp 	rsvd 	RSVD
169 	tcp 	send 	SEND
169 	udp 	send 	SEND
170 	tcp 	print-srv 	Network PostScript
170 	udp 	print-srv 	Network PostScript
171 	tcp 	multiplex 	Network Innovations Multiplex
171 	udp 	multiplex 	Network Innovations Multiplex
172 	tcp 	cl-1 	Network Innovations CL/1
IANA assigned this well-formed service name as a replacement for “cl/1”.
172 	tcp 	cl/1 	Network Innovations CL/1
172 	udp 	cl-1 	Network Innovations CL/1
IANA assigned this well-formed service name as a replacement for “cl/1”.
172 	udp 	cl/1 	Network Innovations CL/1
173 	tcp 	xyplex-mux 	Xyplex
173 	udp 	xyplex-mux 	Xyplex
174 	tcp 	mailq 	MAILQ
174 	udp 	mailq 	MAILQ
175 	tcp 	vmnet 	VMNET
175 	udp 	vmnet 	VMNET
176 	tcp 	genrad-mux 	GENRAD-MUX
176 	udp 	genrad-mux 	GENRAD-MUX
177 	tcp 	xdmcp 	X Display Manager Control Protocol
177 	udp 	xdmcp 	X Display Manager Control Protocol
178 	tcp 	nextstep 	NextStep Window Server
178 	udp 	nextstep 	NextStep Window Server
179 	tcp 	bgp 	Border Gateway Protocol
179 	udp 	bgp 	Border Gateway Protocol
179 	sctp 	bgp 	BGP
180 	tcp 	ris 	Intergraph
180 	udp 	ris 	Intergraph
181 	tcp 	unify 	Unify
181 	udp 	unify 	Unify
182 	tcp 	audit 	Unisys Audit SITP
182 	udp 	audit 	Unisys Audit SITP
183 	tcp 	ocbinder 	OCBinder
183 	udp 	ocbinder 	OCBinder
184 	tcp 	ocserver 	OCServer
184 	udp 	ocserver 	OCServer
185 	tcp 	remote-kis 	Remote-KIS
185 	udp 	remote-kis 	Remote-KIS
186 	tcp 	kis 	KIS Protocol
186 	udp 	kis 	KIS Protocol
187 	tcp 	aci 	Application Communication Interface
187 	udp 	aci 	Application Communication Interface
188 	tcp 	mumps 	Plus Five’s MUMPS
188 	udp 	mumps 	Plus Five’s MUMPS
189 	tcp 	qft 	Queued File Transport
189 	udp 	qft 	Queued File Transport
190 	tcp 	gacp 	Gateway Access Control Protocol
190 	udp 	gacp 	Gateway Access Control Protocol
191 	tcp 	prospero 	Prospero Directory Service
191 	udp 	prospero 	Prospero Directory Service
192 	tcp 	osu-nms 	OSU Network Monitoring System
192 	udp 	osu-nms 	OSU Network Monitoring System
193 	tcp 	srmp 	Spider Remote Monitoring Protocol
193 	udp 	srmp 	Spider Remote Monitoring Protocol
194 	tcp 	irc 	Internet Relay Chat Protocol
194 	udp 	irc 	Internet Relay Chat Protocol
195 	tcp 	dn6-nlm-aud 	DNSIX Network Level Module Audit
195 	udp 	dn6-nlm-aud 	DNSIX Network Level Module Audit
196 	tcp 	dn6-smm-red 	DNSIX Session Mgt Module Audit Redir
196 	udp 	dn6-smm-red 	DNSIX Session Mgt Module Audit Redir
197 	tcp 	dls 	Directory Location Service
197 	udp 	dls 	Directory Location Service
198 	tcp 	dls-mon 	Directory Location Service Monitor
198 	udp 	dls-mon 	Directory Location Service Monitor
199 	tcp 	smux 	SMUX
199 	udp 	smux 	SMUX
200 	tcp 	src 	IBM System Resource Controller
200 	udp 	src 	IBM System Resource Controller
201 	tcp 	at-rtmp 	AppleTalk Routing Maintenance
201 	udp 	at-rtmp 	AppleTalk Routing Maintenance
202 	tcp 	at-nbp 	AppleTalk Name Binding
202 	udp 	at-nbp 	AppleTalk Name Binding
203 	tcp 	at-3 	AppleTalk Unused
203 	udp 	at-3 	AppleTalk Unused
204 	tcp 	at-echo 	AppleTalk Echo
204 	udp 	at-echo 	AppleTalk Echo
205 	tcp 	at-5 	AppleTalk Unused
205 	udp 	at-5 	AppleTalk Unused
206 	tcp 	at-zis 	AppleTalk Zone Information
206 	udp 	at-zis 	AppleTalk Zone Information
207 	tcp 	at-7 	AppleTalk Unused
207 	udp 	at-7 	AppleTalk Unused
208 	tcp 	at-8 	AppleTalk Unused
208 	udp 	at-8 	AppleTalk Unused
209 	tcp 	qmtp 	The Quick Mail Transfer Protocol
209 	udp 	qmtp 	The Quick Mail Transfer Protocol
210 	tcp 	z39-50 	ANSI Z39.50
IANA assigned this well-formed service name as a replacement for “z39.50”.
210 	tcp 	z39.50 	ANSI Z39.50
210 	udp 	z39-50 	ANSI Z39.50
IANA assigned this well-formed service name as a replacement for “z39.50”.
210 	udp 	z39.50 	ANSI Z39.50
211 	tcp 	914c-g 	Texas Instruments 914C/G Terminal
IANA assigned this well-formed service name as a replacement for “914c/g”.
211 	tcp 	914c/g 	Texas Instruments 914C/G Terminal
211 	udp 	914c-g 	Texas Instruments 914C/G Terminal
IANA assigned this well-formed service name as a replacement for “914c/g”.
211 	udp 	914c/g 	Texas Instruments 914C/G Terminal
212 	tcp 	anet 	ATEXSSTR
212 	udp 	anet 	ATEXSSTR
213 	tcp 	ipx 	IPX
213 	udp 	ipx 	IPX
214 	tcp 	vmpwscs 	VM PWSCS
214 	udp 	vmpwscs 	VM PWSCS
215 	tcp 	softpc 	Insignia Solutions
215 	udp 	softpc 	Insignia Solutions
216 	tcp 	CAIlic 	Computer Associates Int’l License Server
216 	udp 	CAIlic 	Computer Associates Int’l License Server
217 	tcp 	dbase 	dBASE Unix
217 	udp 	dbase 	dBASE Unix
218 	tcp 	mpp 	Netix Message Posting Protocol
218 	udp 	mpp 	Netix Message Posting Protocol
219 	tcp 	uarps 	Unisys ARPs
219 	udp 	uarps 	Unisys ARPs
220 	tcp 	imap3 	Interactive Mail Access Protocol v3
220 	udp 	imap3 	Interactive Mail Access Protocol v3
221 	tcp 	fln-spx 	Berkeley rlogind with SPX auth
221 	udp 	fln-spx 	Berkeley rlogind with SPX auth
222 	tcp 	rsh-spx 	Berkeley rshd with SPX auth
222 	udp 	rsh-spx 	Berkeley rshd with SPX auth
223 	tcp 	cdc 	Certificate Distribution Center
223 	udp 	cdc 	Certificate Distribution Center
224 	tcp 	masqdialer 	masqdialer
224 	udp 	masqdialer 	masqdialer
225-241 			Reserved
242 	tcp 	direct 	Direct
242 	udp 	direct 	Direct
243 	tcp 	sur-meas 	Survey Measurement
243 	udp 	sur-meas 	Survey Measurement
244 	tcp 	inbusiness 	inbusiness
244 	udp 	inbusiness 	inbusiness
245 	tcp 	link 	LINK
245 	udp 	link 	LINK
246 	tcp 	dsp3270 	Display Systems Protocol
246 	udp 	dsp3270 	Display Systems Protocol
247 	tcp 	subntbcst-tftp 	SUBNTBCST_TFTP
IANA assigned this well-formed service name as a replacement for “subntbcst_tftp”.
247 	tcp 	subntbcst_tftp 	SUBNTBCST_TFTP
247 	udp 	subntbcst-tftp 	SUBNTBCST_TFTP
IANA assigned this well-formed service name as a replacement for “subntbcst_tftp”.
247 	udp 	subntbcst_tftp 	SUBNTBCST_TFTP
248 	tcp 	bhfhs 	bhfhs
248 	udp 	bhfhs 	bhfhs
249-255 			Reserved
256 	tcp 	rap 	RAP
256 	udp 	rap 	RAP
257 	tcp 	set 	Secure Electronic Transaction
257 	udp 	set 	Secure Electronic Transaction
258 			Unassigned
259 	tcp 	esro-gen 	Efficient Short Remote Operations
259 	udp 	esro-gen 	Efficient Short Remote Operations
260 	tcp 	openport 	Openport
260 	udp 	openport 	Openport
261 	tcp 	nsiiops 	IIOP Name Service over TLS/SSL
261 	udp 	nsiiops 	IIOP Name Service over TLS/SSL
262 	tcp 	arcisdms 	Arcisdms
262 	udp 	arcisdms 	Arcisdms
263 	tcp 	hdap 	HDAP
263 	udp 	hdap 	HDAP
264 	tcp 	bgmp 	BGMP
264 	udp 	bgmp 	BGMP
265 	tcp 	x-bone-ctl 	X-Bone CTL
265 	udp 	x-bone-ctl 	X-Bone CTL
266 	tcp 	sst 	SCSI on ST
266 	udp 	sst 	SCSI on ST
267 	tcp 	td-service 	Tobit David Service Layer
267 	udp 	td-service 	Tobit David Service Layer
268 	tcp 	td-replica 	Tobit David Replica
268 	udp 	td-replica 	Tobit David Replica
269 	tcp 	manet 	MANET Protocols
269 	udp 	manet 	MANET Protocols
270 	tcp 		Reserved
270 	udp 	gist 	Q-mode encapsulation for GIST messages
271 	tcp 	pt-tls 	(NEA) Posture Trans. Protocol over TLS (PT-TLS)
271 	udp 		Reserved
272-279 			Unassigned
280 	tcp 	http-mgmt 	http-mgmt
280 	udp 	http-mgmt 	http-mgmt
281 	tcp 	personal-link 	Personal Link
281 	udp 	personal-link 	Personal Link
282 	tcp 	cableport-ax 	Cable Port A/X
282 	udp 	cableport-ax 	Cable Port A/X
283 	tcp 	rescap 	rescap
283 	udp 	rescap 	rescap
284 	tcp 	corerjd 	corerjd
284 	udp 	corerjd 	corerjd
285 			Unassigned
286 	tcp 	fxp 	FXP Communication
286 	udp 	fxp 	FXP Communication
287 	tcp 	k-block 	K-BLOCK
287 	udp 	k-block 	K-BLOCK
288-307 			Unassigned
308 	tcp 	novastorbakcup 	Novastor Backup
308 	udp 	novastorbakcup 	Novastor Backup
309 	tcp 	entrusttime 	EntrustTime
309 	udp 	entrusttime 	EntrustTime
310 	tcp 	bhmds 	bhmds
310 	udp 	bhmds 	bhmds
311 	tcp 	asip-webadmin 	AppleShare IP WebAdmin
311 	udp 	asip-webadmin 	AppleShare IP WebAdmin
312 	tcp 	vslmp 	VSLMP
312 	udp 	vslmp 	VSLMP
313 	tcp 	magenta-logic 	Magenta Logic
313 	udp 	magenta-logic 	Magenta Logic
314 	tcp 	opalis-robot 	Opalis Robot
314 	udp 	opalis-robot 	Opalis Robot
315 	tcp 	dpsi 	DPSI
315 	udp 	dpsi 	DPSI
316 	tcp 	decauth 	decAuth
316 	udp 	decauth 	decAuth
317 	tcp 	zannet 	Zannet
317 	udp 	zannet 	Zannet
318 	tcp 	pkix-timestamp 	PKIX TimeStamp
318 	udp 	pkix-timestamp 	PKIX TimeStamp
319 	tcp 	ptp-event 	PTP Event
319 	udp 	ptp-event 	PTP Event
320 	tcp 	ptp-general 	PTP General
320 	udp 	ptp-general 	PTP General
321 	tcp 	pip 	PIP
321 	udp 	pip 	PIP
322 	tcp 	rtsps 	RTSPS
322 	udp 	rtsps 	RTSPS
323 	tcp 	rpki-rtr 	Resource PKI to Router Protocol
323 	udp 		Reserved
324 	tcp 	rpki-rtr-tls 	Resource PKI to Router Protocol over TLS
324 	udp 		Reserved
325-332 			Unassigned
333 	tcp 	texar 	Texar Security Port
333 	udp 	texar 	Texar Security Port
334-343 			Unassigned
344 	tcp 	pdap 	Prospero Data Access Protocol
344 	udp 	pdap 	Prospero Data Access Protocol
345 	tcp 	pawserv 	Perf Analysis Workbench
345 	udp 	pawserv 	Perf Analysis Workbench
346 	tcp 	zserv 	Zebra server
346 	udp 	zserv 	Zebra server
347 	tcp 	fatserv 	Fatmen Server
347 	udp 	fatserv 	Fatmen Server
348 	tcp 	csi-sgwp 	Cabletron Management Protocol
348 	udp 	csi-sgwp 	Cabletron Management Protocol
349 	tcp 	mftp 	mftp
349 	udp 	mftp 	mftp
350 	tcp 	matip-type-a 	MATIP Type A
350 	udp 	matip-type-a 	MATIP Type A
351 	tcp 	matip-type-b 	MATIP Type B
351 	udp 	matip-type-b 	MATIP Type B
351 	tcp 	bhoetty 	bhoetty
351 	udp 	bhoetty 	bhoetty
352 	tcp 	dtag-ste-sb 	DTAG
352 	udp 	dtag-ste-sb 	DTAG
352 	tcp 	bhoedap4 	bhoedap4
352 	udp 	bhoedap4 	bhoedap4
353 	tcp 	ndsauth 	NDSAUTH
353 	udp 	ndsauth 	NDSAUTH
354 	tcp 	bh611 	bh611
354 	udp 	bh611 	bh611
355 	tcp 	datex-asn 	DATEX-ASN
355 	udp 	datex-asn 	DATEX-ASN
356 	tcp 	cloanto-net-1 	Cloanto Net 1
356 	udp 	cloanto-net-1 	Cloanto Net 1
357 	tcp 	bhevent 	bhevent
357 	udp 	bhevent 	bhevent
358 	tcp 	shrinkwrap 	Shrinkwrap
358 	udp 	shrinkwrap 	Shrinkwrap
359 	tcp 	nsrmp 	Network Security Risk Management Protocol
359 	udp 	nsrmp 	Network Security Risk Management Protocol
360 	tcp 	scoi2odialog 	scoi2odialog
360 	udp 	scoi2odialog 	scoi2odialog
361 	tcp 	semantix 	Semantix
361 	udp 	semantix 	Semantix
362 	tcp 	srssend 	SRS Send
362 	udp 	srssend 	SRS Send
363 	tcp 	rsvp-tunnel 	RSVP Tunnel
IANA assigned this well-formed service name as a replacement for “rsvp_tunnel”.
363 	tcp 	rsvp_tunnel 	RSVP Tunnel
363 	udp 	rsvp-tunnel 	RSVP Tunnel
IANA assigned this well-formed service name as a replacement for “rsvp_tunnel”.
363 	udp 	rsvp_tunnel 	RSVP Tunnel
364 	tcp 	aurora-cmgr 	Aurora CMGR
364 	udp 	aurora-cmgr 	Aurora CMGR
365 	tcp 	dtk 	DTK
365 	udp 	dtk 	DTK
366 	tcp 	odmr 	ODMR
366 	udp 	odmr 	ODMR
367 	tcp 	mortgageware 	MortgageWare
367 	udp 	mortgageware 	MortgageWare
368 	tcp 	qbikgdp 	QbikGDP
368 	udp 	qbikgdp 	QbikGDP
369 	tcp 	rpc2portmap 	rpc2portmap
369 	udp 	rpc2portmap 	rpc2portmap
370 	tcp 	codaauth2 	codaauth2
370 	udp 	codaauth2 	codaauth2
371 	tcp 	clearcase 	Clearcase
371 	udp 	clearcase 	Clearcase
372 	tcp 	ulistproc 	ListProcessor
372 	udp 	ulistproc 	ListProcessor
373 	tcp 	legent-1 	Legent Corporation
373 	udp 	legent-1 	Legent Corporation
374 	tcp 	legent-2 	Legent Corporation
374 	udp 	legent-2 	Legent Corporation
375 	tcp 	hassle 	Hassle
375 	udp 	hassle 	Hassle
376 	tcp 	nip 	Amiga Envoy Network Inquiry Proto
376 	udp 	nip 	Amiga Envoy Network Inquiry Proto
377 	tcp 	tnETOS 	NEC Corporation
377 	udp 	tnETOS 	NEC Corporation
378 	tcp 	dsETOS 	NEC Corporation
378 	udp 	dsETOS 	NEC Corporation
379 	tcp 	is99c 	TIA/EIA/IS-99 modem client
379 	udp 	is99c 	TIA/EIA/IS-99 modem client
380 	tcp 	is99s 	TIA/EIA/IS-99 modem server
380 	udp 	is99s 	TIA/EIA/IS-99 modem server
381 	tcp 	hp-collector 	hp performance data collector
381 	udp 	hp-collector 	hp performance data collector
382 	tcp 	hp-managed-node 	hp performance data managed node
382 	udp 	hp-managed-node 	hp performance data managed node
383 	tcp 	hp-alarm-mgr 	hp performance data alarm manager
383 	udp 	hp-alarm-mgr 	hp performance data alarm manager
384 	tcp 	arns 	A Remote Network Server System
384 	udp 	arns 	A Remote Network Server System
385 	tcp 	ibm-app 	IBM Application
385 	udp 	ibm-app 	IBM Application
386 	tcp 	asa 	ASA Message Router Object Def.
386 	udp 	asa 	ASA Message Router Object Def.
387 	tcp 	aurp 	Appletalk Update-Based Routing Pro.
387 	udp 	aurp 	Appletalk Update-Based Routing Pro.
388 	tcp 	unidata-ldm 	Unidata LDM
388 	udp 	unidata-ldm 	Unidata LDM
389 	tcp 	ldap 	Lightweight Directory Access Protocol
389 	udp 	ldap 	Lightweight Directory Access Protocol
390 	tcp 	uis 	UIS
390 	udp 	uis 	UIS
391 	tcp 	synotics-relay 	SynOptics SNMP Relay Port
391 	udp 	synotics-relay 	SynOptics SNMP Relay Port
392 	tcp 	synotics-broker 	SynOptics Port Broker Port
392 	udp 	synotics-broker 	SynOptics Port Broker Port
393 	tcp 	meta5 	Meta5
393 	udp 	meta5 	Meta5
394 	tcp 	embl-ndt 	EMBL Nucleic Data Transfer
394 	udp 	embl-ndt 	EMBL Nucleic Data Transfer
395 	tcp 	netcp 	NetScout Control Protocol
395 	udp 	netcp 	NetScout Control Protocol
396 	tcp 	netware-ip 	Novell Netware over IP
396 	udp 	netware-ip 	Novell Netware over IP
397 	tcp 	mptn 	Multi Protocol Trans. Net.
397 	udp 	mptn 	Multi Protocol Trans. Net.
398 	tcp 	kryptolan 	Kryptolan
398 	udp 	kryptolan 	Kryptolan
399 	tcp 	iso-tsap-c2 	ISO Transport Class 2 Non-Control over TCP
399 	udp 	iso-tsap-c2 	ISO Transport Class 2 Non-Control over UDP
400 	tcp 	osb-sd 	Oracle Secure Backup
400 	udp 	osb-sd 	Oracle Secure Backup
401 	tcp 	ups 	Uninterruptible Power Supply
401 	udp 	ups 	Uninterruptible Power Supply
402 	tcp 	genie 	Genie Protocol
402 	udp 	genie 	Genie Protocol
403 	tcp 	decap 	decap
403 	udp 	decap 	decap
404 	tcp 	nced 	nced
404 	udp 	nced 	nced
405 	tcp 	ncld 	ncld
405 	udp 	ncld 	ncld
406 	tcp 	imsp 	Interactive Mail Support Protocol
406 	udp 	imsp 	Interactive Mail Support Protocol
407 	tcp 	timbuktu 	Timbuktu
407 	udp 	timbuktu 	Timbuktu
408 	tcp 	prm-sm 	Prospero Resource Manager Sys. Man.
408 	udp 	prm-sm 	Prospero Resource Manager Sys. Man.
409 	tcp 	prm-nm 	Prospero Resource Manager Node Man.
409 	udp 	prm-nm 	Prospero Resource Manager Node Man.
410 	tcp 	decladebug 	DECLadebug Remote Debug Protocol
410 	udp 	decladebug 	DECLadebug Remote Debug Protocol
411 	tcp 	rmt 	Remote MT Protocol
411 	udp 	rmt 	Remote MT Protocol
412 	tcp 	synoptics-trap 	Trap Convention Port
412 	udp 	synoptics-trap 	Trap Convention Port
413 	tcp 	smsp 	Storage Management Services Protocol
413 	udp 	smsp 	Storage Management Services Protocol
414 	tcp 	infoseek 	InfoSeek
414 	udp 	infoseek 	InfoSeek
415 	tcp 	bnet 	BNet
415 	udp 	bnet 	BNet
416 	tcp 	silverplatter 	Silverplatter
416 	udp 	silverplatter 	Silverplatter
417 	tcp 	onmux 	Onmux
417 	udp 	onmux 	Onmux
418 	tcp 	hyper-g 	Hyper-G
418 	udp 	hyper-g 	Hyper-G
419 	tcp 	ariel1 	Ariel 1
419 	udp 	ariel1 	Ariel 1
420 	tcp 	smpte 	SMPTE
420 	udp 	smpte 	SMPTE
421 	tcp 	ariel2 	Ariel 2
421 	udp 	ariel2 	Ariel 2
422 	tcp 	ariel3 	Ariel 3
422 	udp 	ariel3 	Ariel 3
423 	tcp 	opc-job-start 	IBM Operations Planning and Control Start
423 	udp 	opc-job-start 	IBM Operations Planning and Control Start
424 	tcp 	opc-job-track 	IBM Operations Planning and Control Track
424 	udp 	opc-job-track 	IBM Operations Planning and Control Track
425 	tcp 	icad-el 	ICAD
425 	udp 	icad-el 	ICAD
426 	tcp 	smartsdp 	smartsdp
426 	udp 	smartsdp 	smartsdp
427 	tcp 	svrloc 	Server Location
427 	udp 	svrloc 	Server Location
428 	tcp 	ocs-cmu 	OCS_CMU
IANA assigned this well-formed service name as a replacement for “ocs_cmu”.
428 	tcp 	ocs_cmu 	OCS_CMU
428 	udp 	ocs-cmu 	OCS_CMU
IANA assigned this well-formed service name as a replacement for “ocs_cmu”.
428 	udp 	ocs_cmu 	OCS_CMU
429 	tcp 	ocs-amu 	OCS_AMU
IANA assigned this well-formed service name as a replacement for “ocs_amu”.
429 	tcp 	ocs_amu 	OCS_AMU
429 	udp 	ocs-amu 	OCS_AMU
IANA assigned this well-formed service name as a replacement for “ocs_amu”.
429 	udp 	ocs_amu 	OCS_AMU
430 	tcp 	utmpsd 	UTMPSD
430 	udp 	utmpsd 	UTMPSD
431 	tcp 	utmpcd 	UTMPCD
431 	udp 	utmpcd 	UTMPCD
432 	tcp 	iasd 	IASD
432 	udp 	iasd 	IASD
433 	tcp 	nnsp 	NNTP for transit servers (NNSP)
433 	udp 	nnsp 	NNTP for transit servers (NNSP)
434 	tcp 	mobileip-agent 	MobileIP-Agent
434 	udp 	mobileip-agent 	MobileIP-Agent
435 	tcp 	mobilip-mn 	MobilIP-MN
435 	udp 	mobilip-mn 	MobilIP-MN
436 	tcp 	dna-cml 	DNA-CML
436 	udp 	dna-cml 	DNA-CML
437 	tcp 	comscm 	comscm
437 	udp 	comscm 	comscm
438 	tcp 	dsfgw 	dsfgw
438 	udp 	dsfgw 	dsfgw
439 	tcp 	dasp 	dasp
439 	udp 	dasp 	dasp
440 	tcp 	sgcp 	sgcp
440 	udp 	sgcp 	sgcp
441 	tcp 	decvms-sysmgt 	decvms-sysmgt
441 	udp 	decvms-sysmgt 	decvms-sysmgt
442 	tcp 	cvc-hostd 	cvc_hostd
IANA assigned this well-formed service name as a replacement for “cvc_hostd”.
442 	tcp 	cvc_hostd 	cvc_hostd
442 	udp 	cvc-hostd 	cvc_hostd
IANA assigned this well-formed service name as a replacement for “cvc_hostd”.
442 	udp 	cvc_hostd 	cvc_hostd
443 	tcp 	https 	http protocol over TLS/SSL
443 	udp 	https 	http protocol over TLS/SSL
443 	sctp 	https 	HTTPS
444 	tcp 	snpp 	Simple Network Paging Protocol
444 	udp 	snpp 	Simple Network Paging Protocol
445 	tcp 	microsoft-ds 	Microsoft-DS
445 	udp 	microsoft-ds 	Microsoft-DS
446 	tcp 	ddm-rdb 	DDM-Remote Relational Database Access
446 	udp 	ddm-rdb 	DDM-Remote Relational Database Access
447 	tcp 	ddm-dfm 	DDM-Distributed File Management
447 	udp 	ddm-dfm 	DDM-Distributed File Management
448 	tcp 	ddm-ssl 	DDM-Remote DB Access Using Secure Sockets
448 	udp 	ddm-ssl 	DDM-Remote DB Access Using Secure Sockets
449 	tcp 	as-servermap 	AS Server Mapper
449 	udp 	as-servermap 	AS Server Mapper
450 	tcp 	tserver 	Computer Supported Telecomunication App
450 	udp 	tserver 	Computer Supported Telecomunication App
451 	tcp 	sfs-smp-net 	Cray Network Semaphore server
451 	udp 	sfs-smp-net 	Cray Network Semaphore server
452 	tcp 	sfs-config 	Cray SFS config server
452 	udp 	sfs-config 	Cray SFS config server
453 	tcp 	creativeserver 	CreativeServer
453 	udp 	creativeserver 	CreativeServer
454 	tcp 	contentserver 	ContentServer
454 	udp 	contentserver 	ContentServer
455 	tcp 	creativepartnr 	CreativePartnr
455 	udp 	creativepartnr 	CreativePartnr
456 	tcp 	macon-tcp 	macon-tcp
456 	udp 	macon-udp 	macon-udp
457 	tcp 	scohelp 	scohelp
457 	udp 	scohelp 	scohelp
458 	tcp 	appleqtc 	apple quick time
458 	udp 	appleqtc 	apple quick time
459 	tcp 	ampr-rcmd 	ampr-rcmd
459 	udp 	ampr-rcmd 	ampr-rcmd
460 	tcp 	skronk 	skronk
460 	udp 	skronk 	skronk
461 	tcp 	datasurfsrv 	DataRampSrv
461 	udp 	datasurfsrv 	DataRampSrv
462 	tcp 	datasurfsrvsec 	DataRampSrvSec
462 	udp 	datasurfsrvsec 	DataRampSrvSec
463 	tcp 	alpes 	alpes
463 	udp 	alpes 	alpes
464 	tcp 	kpasswd 	kpasswd
464 	udp 	kpasswd 	kpasswd
465 	tcp 	urd 	URL Rendesvous Directory for SSM
465 	udp 	igmpv3lite 	IGMP over UDP for SSM
466 	tcp 	digital-vrc 	digital-vrc
466 	udp 	digital-vrc 	digital-vrc
467 	tcp 	mylex-mapd 	mylex-mapd
467 	udp 	mylex-mapd 	mylex-mapd
468 	tcp 	photuris 	proturis
468 	udp 	photuris 	proturis
469 	tcp 	rcp 	Radio Control Protocol
469 	udp 	rcp 	Radio Control Protocol
470 	tcp 	scx-proxy 	scx-proxy
470 	udp 	scx-proxy 	scx-proxy
471 	tcp 	mondex 	Mondex
471 	udp 	mondex 	Mondex
472 	tcp 	ljk-login 	ljk-login
472 	udp 	ljk-login 	ljk-login
473 	tcp 	hybrid-pop 	hybrid-pop
473 	udp 	hybrid-pop 	hybrid-pop
474 	tcp 	tn-tl-w1 	tn-tl-w1
474 	udp 	tn-tl-w2 	tn-tl-w2
475 	tcp 	tcpnethaspsrv 	tcpnethaspsrv
475 	udp 	tcpnethaspsrv 	tcpnethaspsrv
476 	tcp 	tn-tl-fd1 	tn-tl-fd1
476 	udp 	tn-tl-fd1 	tn-tl-fd1
477 	tcp 	ss7ns 	ss7ns
477 	udp 	ss7ns 	ss7ns
478 	tcp 	spsc 	spsc
478 	udp 	spsc 	spsc
479 	tcp 	iafserver 	iafserver
479 	udp 	iafserver 	iafserver
480 	tcp 	iafdbase 	iafdbase
480 	udp 	iafdbase 	iafdbase
481 	tcp 	ph 	Ph service
481 	udp 	ph 	Ph service
482 	tcp 	bgs-nsi 	bgs-nsi
482 	udp 	bgs-nsi 	bgs-nsi
483 	tcp 	ulpnet 	ulpnet
483 	udp 	ulpnet 	ulpnet
484 	tcp 	integra-sme 	Integra Software Management Environment
484 	udp 	integra-sme 	Integra Software Management Environment
485 	tcp 	powerburst 	Air Soft Power Burst
485 	udp 	powerburst 	Air Soft Power Burst
486 	tcp 	avian 	avian
486 	udp 	avian 	avian
487 	tcp 	saft 	saft Simple Asynchronous File Transfer
487 	udp 	saft 	saft Simple Asynchronous File Transfer
488 	tcp 	gss-http 	gss-http
488 	udp 	gss-http 	gss-http
489 	tcp 	nest-protocol 	nest-protocol
489 	udp 	nest-protocol 	nest-protocol
490 	tcp 	micom-pfs 	micom-pfs
490 	udp 	micom-pfs 	micom-pfs
491 	tcp 	go-login 	go-login
491 	udp 	go-login 	go-login
492 	tcp 	ticf-1 	Transport Independent Convergence for FNA
492 	udp 	ticf-1 	Transport Independent Convergence for FNA
493 	tcp 	ticf-2 	Transport Independent Convergence for FNA
493 	udp 	ticf-2 	Transport Independent Convergence for FNA
494 	tcp 	pov-ray 	POV-Ray
494 	udp 	pov-ray 	POV-Ray
495 	tcp 	intecourier 	intecourier
495 	udp 	intecourier 	intecourier
496 	tcp 	pim-rp-disc 	PIM-RP-DISC
496 	udp 	pim-rp-disc 	PIM-RP-DISC
497 	tcp 	retrospect 	Retrospect backup and restore service
497 	udp 	retrospect 	Retrospect backup and restore service
498 	tcp 	siam 	siam
498 	udp 	siam 	siam
499 	tcp 	iso-ill 	ISO ILL Protocol
499 	udp 	iso-ill 	ISO ILL Protocol
500 	tcp 	isakmp 	isakmp
500 	udp 	isakmp 	isakmp
501 	tcp 	stmf 	STMF
501 	udp 	stmf 	STMF
502 	tcp 	mbap 	Modbus Application Protocol
502 	udp 	mbap 	Modbus Application Protocol
503 	tcp 	intrinsa 	Intrinsa
503 	udp 	intrinsa 	Intrinsa
504 	tcp 	citadel 	citadel
504 	udp 	citadel 	citadel
505 	tcp 	mailbox-lm 	mailbox-lm
505 	udp 	mailbox-lm 	mailbox-lm
506 	tcp 	ohimsrv 	ohimsrv
506 	udp 	ohimsrv 	ohimsrv
507 	tcp 	crs 	crs
507 	udp 	crs 	crs
508 	tcp 	xvttp 	xvttp
508 	udp 	xvttp 	xvttp
509 	tcp 	snare 	snare
509 	udp 	snare 	snare
510 	tcp 	fcp 	FirstClass Protocol
510 	udp 	fcp 	FirstClass Protocol
511 	tcp 	passgo 	PassGo
511 	udp 	passgo 	PassGo
512 	tcp 	exec 	remote process execution;
512 	udp 	comsat 	
512 	udp 	biff 	used by mail system to notify users of new mail
513 	tcp 	login 	remote login a la telnet
513 	udp 	who 	maintains data bases showing logins
514 	tcp 	shell 	cmd like exec, but automatic authentication
514 	udp 	syslog 	
515 	tcp 	printer 	spooler
515 	udp 	printer 	spooler
516 	tcp 	videotex 	videotex
516 	udp 	videotex 	videotex
517 	tcp 	talk 	like tenex link
517 	udp 	talk 	like tenex link
518 	tcp 	ntalk 	
518 	udp 	ntalk 	
519 	tcp 	utime 	unixtime
519 	udp 	utime 	unixtime
520 	tcp 	efs 	extended file name server
520 	udp 	router 	local routing process (on site); RIP variant
521 	tcp 	ripng 	ripng
521 	udp 	ripng 	ripng
522 	tcp 	ulp 	ULP
522 	udp 	ulp 	ULP
523 	tcp 	ibm-db2 	IBM-DB2
523 	udp 	ibm-db2 	IBM-DB2
524 	tcp 	ncp 	NCP
524 	udp 	ncp 	NCP
525 	tcp 	timed 	timeserver
525 	udp 	timed 	timeserver
526 	tcp 	tempo 	newdate
526 	udp 	tempo 	newdate
527 	tcp 	stx 	Stock IXChange
527 	udp 	stx 	Stock IXChange
528 	tcp 	custix 	Customer IXChange
528 	udp 	custix 	Customer IXChange
529 	tcp 	irc-serv 	IRC-SERV
529 	udp 	irc-serv 	IRC-SERV
530 	tcp 	courier 	rpc
530 	udp 	courier 	rpc
531 	tcp 	conference 	chat
531 	udp 	conference 	chat
532 	tcp 	netnews 	readnews
532 	udp 	netnews 	readnews
533 	tcp 	netwall 	for emergency broadcasts
533 	udp 	netwall 	for emergency broadcasts
534 	tcp 	windream 	windream Admin
534 	udp 	windream 	windream Admin
535 	tcp 	iiop 	iiop
535 	udp 	iiop 	iiop
536 	tcp 	opalis-rdv 	opalis-rdv
536 	udp 	opalis-rdv 	opalis-rdv
537 	tcp 	nmsp 	Networked Media Streaming Protocol
537 	udp 	nmsp 	Networked Media Streaming Protocol
538 	tcp 	gdomap 	gdomap
538 	udp 	gdomap 	gdomap
539 	tcp 	apertus-ldp 	Apertus Technologies Load Determination
539 	udp 	apertus-ldp 	Apertus Technologies Load Determination
540 	tcp 	uucp 	uucpd
540 	udp 	uucp 	uucpd
541 	tcp 	uucp-rlogin 	uucp-rlogin
541 	udp 	uucp-rlogin 	uucp-rlogin
542 	tcp 	commerce 	commerce
542 	udp 	commerce 	commerce
543 	tcp 	klogin 	
543 	udp 	klogin 	
544 	tcp 	kshell 	krcmd
544 	udp 	kshell 	krcmd
545 	tcp 	appleqtcsrvr 	appleqtcsrvr
545 	udp 	appleqtcsrvr 	appleqtcsrvr
546 	tcp 	dhcpv6-client 	DHCPv6 Client
546 	udp 	dhcpv6-client 	DHCPv6 Client
547 	tcp 	dhcpv6-server 	DHCPv6 Server
547 	udp 	dhcpv6-server 	DHCPv6 Server
548 	tcp 	afpovertcp 	AFP over TCP
548 	udp 	afpovertcp 	AFP over TCP
549 	tcp 	idfp 	IDFP
549 	udp 	idfp 	IDFP
550 	tcp 	new-rwho 	new-who
550 	udp 	new-rwho 	new-who
551 	tcp 	cybercash 	cybercash
551 	udp 	cybercash 	cybercash
552 	tcp 	devshr-nts 	DeviceShare
552 	udp 	devshr-nts 	DeviceShare
553 	tcp 	pirp 	pirp
553 	udp 	pirp 	pirp
554 	tcp 	rtsp 	Real Time Streaming Protocol (RTSP)
554 	udp 	rtsp 	Real Time Streaming Protocol (RTSP)
555 	tcp 	dsf 	
555 	udp 	dsf 	
556 	tcp 	remotefs 	rfs server
556 	udp 	remotefs 	rfs server
557 	tcp 	openvms-sysipc 	openvms-sysipc
557 	udp 	openvms-sysipc 	openvms-sysipc
558 	tcp 	sdnskmp 	SDNSKMP
558 	udp 	sdnskmp 	SDNSKMP
559 	tcp 	teedtap 	TEEDTAP
559 	udp 	teedtap 	TEEDTAP
560 	tcp 	rmonitor 	rmonitord
560 	udp 	rmonitor 	rmonitord
561 	tcp 	monitor 	
561 	udp 	monitor 	
562 	tcp 	chshell 	chcmd
562 	udp 	chshell 	chcmd
563 	tcp 	nntps 	nntp protocol over TLS/SSL (was snntp)
563 	udp 	nntps 	nntp protocol over TLS/SSL (was snntp)
564 	tcp 	9pfs 	plan 9 file service
564 	udp 	9pfs 	plan 9 file service
565 	tcp 	whoami 	whoami
565 	udp 	whoami 	whoami
566 	tcp 	streettalk 	streettalk
566 	udp 	streettalk 	streettalk
567 	tcp 	banyan-rpc 	banyan-rpc
567 	udp 	banyan-rpc 	banyan-rpc
568 	tcp 	ms-shuttle 	microsoft shuttle
568 	udp 	ms-shuttle 	microsoft shuttle
569 	tcp 	ms-rome 	microsoft rome
569 	udp 	ms-rome 	microsoft rome
570 	tcp 	meter 	demon
570 	udp 	meter 	demon
571 	tcp 	meter 	udemon
571 	udp 	meter 	udemon
572 	tcp 	sonar 	sonar
572 	udp 	sonar 	sonar
573 	tcp 	banyan-vip 	banyan-vip
573 	udp 	banyan-vip 	banyan-vip
574 	tcp 	ftp-agent 	FTP Software Agent System
574 	udp 	ftp-agent 	FTP Software Agent System
575 	tcp 	vemmi 	VEMMI
575 	udp 	vemmi 	VEMMI
576 	tcp 	ipcd 	ipcd
576 	udp 	ipcd 	ipcd
577 	tcp 	vnas 	vnas
577 	udp 	vnas 	vnas
578 	tcp 	ipdd 	ipdd
578 	udp 	ipdd 	ipdd
579 	tcp 	decbsrv 	decbsrv
579 	udp 	decbsrv 	decbsrv
580 	tcp 	sntp-heartbeat 	SNTP HEARTBEAT
580 	udp 	sntp-heartbeat 	SNTP HEARTBEAT
581 	tcp 	bdp 	Bundle Discovery Protocol
581 	udp 	bdp 	Bundle Discovery Protocol
582 	tcp 	scc-security 	SCC Security
582 	udp 	scc-security 	SCC Security
583 	tcp 	philips-vc 	Philips Video-Conferencing
583 	udp 	philips-vc 	Philips Video-Conferencing
584 	tcp 	keyserver 	Key Server
584 	udp 	keyserver 	Key Server
585 			De-registered
586 	tcp 	password-chg 	Password Change
586 	udp 	password-chg 	Password Change
587 	tcp 	submission 	Message Submission
587 	udp 	submission 	Message Submission
588 	tcp 	cal 	CAL
588 	udp 	cal 	CAL
589 	tcp 	eyelink 	EyeLink
589 	udp 	eyelink 	EyeLink
590 	tcp 	tns-cml 	TNS CML
590 	udp 	tns-cml 	TNS CML
591 	tcp 	http-alt 	FileMaker, Inc. – HTTP Alternate (see Port 80)
591 	udp 	http-alt 	FileMaker, Inc. – HTTP Alternate (see Port 80)
592 	tcp 	eudora-set 	Eudora Set
592 	udp 	eudora-set 	Eudora Set
593 	tcp 	http-rpc-epmap 	HTTP RPC Ep Map
593 	udp 	http-rpc-epmap 	HTTP RPC Ep Map
594 	tcp 	tpip 	TPIP
594 	udp 	tpip 	TPIP
595 	tcp 	cab-protocol 	CAB Protocol
595 	udp 	cab-protocol 	CAB Protocol
596 	tcp 	smsd 	SMSD
596 	udp 	smsd 	SMSD
597 	tcp 	ptcnameservice 	PTC Name Service
597 	udp 	ptcnameservice 	PTC Name Service
598 	tcp 	sco-websrvrmg3 	SCO Web Server Manager 3
598 	udp 	sco-websrvrmg3 	SCO Web Server Manager 3
599 	tcp 	acp 	Aeolon Core Protocol
599 	udp 	acp 	Aeolon Core Protocol
600 	tcp 	ipcserver 	Sun IPC server
600 	udp 	ipcserver 	Sun IPC server
601 	tcp 	syslog-conn 	Reliable Syslog Service
601 	udp 	syslog-conn 	Reliable Syslog Service
602 	tcp 	xmlrpc-beep 	XML-RPC over BEEP
602 	udp 	xmlrpc-beep 	XML-RPC over BEEP
603 	tcp 	idxp 	IDXP
603 	udp 	idxp 	IDXP
604 	tcp 	tunnel 	TUNNEL
604 	udp 	tunnel 	TUNNEL
605 	tcp 	soap-beep 	SOAP over BEEP
605 	udp 	soap-beep 	SOAP over BEEP
606 	tcp 	urm 	Cray Unified Resource Manager
606 	udp 	urm 	Cray Unified Resource Manager
607 	tcp 	nqs 	nqs
607 	udp 	nqs 	nqs
608 	tcp 	sift-uft 	Sender-Initiated/Unsolicited File Transfer
608 	udp 	sift-uft 	Sender-Initiated/Unsolicited File Transfer
609 	tcp 	npmp-trap 	npmp-trap
609 	udp 	npmp-trap 	npmp-trap
610 	tcp 	npmp-local 	npmp-local
610 	udp 	npmp-local 	npmp-local
611 	tcp 	npmp-gui 	npmp-gui
611 	udp 	npmp-gui 	npmp-gui
612 	tcp 	hmmp-ind 	HMMP Indication
612 	udp 	hmmp-ind 	HMMP Indication
613 	tcp 	hmmp-op 	HMMP Operation
613 	udp 	hmmp-op 	HMMP Operation
614 	tcp 	sshell 	SSLshell
614 	udp 	sshell 	SSLshell
615 	tcp 	sco-inetmgr 	Internet Configuration Manager
615 	udp 	sco-inetmgr 	Internet Configuration Manager
616 	tcp 	sco-sysmgr 	SCO System Administration Server
616 	udp 	sco-sysmgr 	SCO System Administration Server
617 	tcp 	sco-dtmgr 	SCO Desktop Administration Server
617 	udp 	sco-dtmgr 	SCO Desktop Administration Server
618 	tcp 	dei-icda 	DEI-ICDA
618 	udp 	dei-icda 	DEI-ICDA
619 	tcp 	compaq-evm 	Compaq EVM
619 	udp 	compaq-evm 	Compaq EVM
620 	tcp 	sco-websrvrmgr 	SCO WebServer Manager
620 	udp 	sco-websrvrmgr 	SCO WebServer Manager
621 	tcp 	escp-ip 	ESCP
621 	udp 	escp-ip 	ESCP
622 	tcp 	collaborator 	Collaborator
622 	udp 	collaborator 	Collaborator
623 	tcp 	oob-ws-http 	DMTF out-of-band web mgt protocol
623 	udp 	asf-rmcp 	ASF Remote Management and Control Protocol
624 	tcp 	cryptoadmin 	Crypto Admin
624 	udp 	cryptoadmin 	Crypto Admin
625 	tcp 	dec-dlm 	DEC DLM
IANA assigned this well-formed service name as a replacement for “dec_dlm”.
625 	tcp 	dec_dlm 	DEC DLM
625 	udp 	dec-dlm 	DEC DLM
IANA assigned this well-formed service name as a replacement for “dec_dlm”.
625 	udp 	dec_dlm 	DEC DLM
626 	tcp 	asia 	ASIA
626 	udp 	asia 	ASIA
627 	tcp 	passgo-tivoli 	PassGo Tivoli
627 	udp 	passgo-tivoli 	PassGo Tivoli
628 	tcp 	qmqp 	QMQP
628 	udp 	qmqp 	QMQP
629 	tcp 	3com-amp3 	3Com AMP3
629 	udp 	3com-amp3 	3Com AMP3
630 	tcp 	rda 	RDA
630 	udp 	rda 	RDA
631 	tcp 	ipp 	IPP (Internet Printing Protocol)
631 	udp 	ipp 	IPP (Internet Printing Protocol)
632 	tcp 	bmpp 	bmpp
632 	udp 	bmpp 	bmpp
633 	tcp 	servstat 	Service Status update (Sterling Software)
633 	udp 	servstat 	Service Status update (Sterling Software)
634 	tcp 	ginad 	ginad
634 	udp 	ginad 	ginad
635 	tcp 	rlzdbase 	RLZ DBase
635 	udp 	rlzdbase 	RLZ DBase
636 	tcp 	ldaps 	ldap protocol over TLS/SSL (was sldap)
636 	udp 	ldaps 	ldap protocol over TLS/SSL (was sldap)
637 	tcp 	lanserver 	lanserver
637 	udp 	lanserver 	lanserver
638 	tcp 	mcns-sec 	mcns-sec
638 	udp 	mcns-sec 	mcns-sec
639 	tcp 	msdp 	MSDP
639 	udp 	msdp 	MSDP
640 	tcp 	entrust-sps 	entrust-sps
640 	udp 	entrust-sps 	entrust-sps
641 	tcp 	repcmd 	repcmd
641 	udp 	repcmd 	repcmd
642 	tcp 	esro-emsdp 	ESRO-EMSDP V1.3
642 	udp 	esro-emsdp 	ESRO-EMSDP V1.3
643 	tcp 	sanity 	SANity
643 	udp 	sanity 	SANity
644 	tcp 	dwr 	dwr
644 	udp 	dwr 	dwr
645 	tcp 	pssc 	PSSC
645 	udp 	pssc 	PSSC
646 	tcp 	ldp 	LDP
646 	udp 	ldp 	LDP
647 	tcp 	dhcp-failover 	DHCP Failover
647 	udp 	dhcp-failover 	DHCP Failover
648 	tcp 	rrp 	Registry Registrar Protocol (RRP)
648 	udp 	rrp 	Registry Registrar Protocol (RRP)
649 	tcp 	cadview-3d 	Cadview-3d – streaming 3d models over the net
649 	udp 	cadview-3d 	Cadview-3d – streaming 3d models over the net
650 	tcp 	obex 	OBEX
650 	udp 	obex 	OBEX
651 	tcp 	ieee-mms 	IEEE MMS
651 	udp 	ieee-mms 	IEEE MMS
652 	tcp 	hello-port 	HELLO_PORT
652 	udp 	hello-port 	HELLO_PORT
653 	tcp 	repscmd 	RepCmd
653 	udp 	repscmd 	RepCmd
654 	tcp 	aodv 	AODV
654 	udp 	aodv 	AODV
655 	tcp 	tinc 	TINC
655 	udp 	tinc 	TINC
656 	tcp 	spmp 	SPMP
656 	udp 	spmp 	SPMP
657 	tcp 	rmc 	RMC
657 	udp 	rmc 	RMC
658 	tcp 	tenfold 	TenFold
658 	udp 	tenfold 	TenFold
659 			Removed
660 	tcp 	mac-srvr-admin 	MacOS Server Admin
660 	udp 	mac-srvr-admin 	MacOS Server Admin
661 	tcp 	hap 	HAP
661 	udp 	hap 	HAP
662 	tcp 	pftp 	PFTP
662 	udp 	pftp 	PFTP
663 	tcp 	purenoise 	PureNoise
663 	udp 	purenoise 	PureNoise
664 	tcp 	oob-ws-https 	DMTF out-of-band secure web services mgt prot
664 	udp 	asf-secure-rmcp 	ASF Secure Remote Mgt and Control Prot
665 	tcp 	sun-dr 	Sun DR
665 	udp 	sun-dr 	Sun DR
666 	tcp 	mdqs 	
666 	udp 	mdqs 	
666 	tcp 	doom 	doom Id Software
666 	udp 	doom 	doom Id Software
667 	tcp 	disclose 	campaign contribution disclosures – SDR Tech
667 	udp 	disclose 	campaign contribution disclosures – SDR Tech
668 	tcp 	mecomm 	MeComm
668 	udp 	mecomm 	MeComm
669 	tcp 	meregister 	MeRegister
669 	udp 	meregister 	MeRegister
670 	tcp 	vacdsm-sws 	VACDSM-SWS
670 	udp 	vacdsm-sws 	VACDSM-SWS
671 	tcp 	vacdsm-app 	VACDSM-APP
671 	udp 	vacdsm-app 	VACDSM-APP
672 	tcp 	vpps-qua 	VPPS-QUA
672 	udp 	vpps-qua 	VPPS-QUA
673 	tcp 	cimplex 	CIMPLEX
673 	udp 	cimplex 	CIMPLEX
674 	tcp 	acap 	ACAP
674 	udp 	acap 	ACAP
675 	tcp 	dctp 	DCTP
675 	udp 	dctp 	DCTP
676 	tcp 	vpps-via 	VPPS Via
676 	udp 	vpps-via 	VPPS Via
677 	tcp 	vpp 	Virtual Presence Protocol
677 	udp 	vpp 	Virtual Presence Protocol
678 	tcp 	ggf-ncp 	GNU Generation Foundation NCP
678 	udp 	ggf-ncp 	GNU Generation Foundation NCP
679 	tcp 	mrm 	MRM
679 	udp 	mrm 	MRM
680 	tcp 	entrust-aaas 	entrust-aaas
680 	udp 	entrust-aaas 	entrust-aaas
681 	tcp 	entrust-aams 	entrust-aams
681 	udp 	entrust-aams 	entrust-aams
682 	tcp 	xfr 	XFR
682 	udp 	xfr 	XFR
683 	tcp 	corba-iiop 	CORBA IIOP
683 	udp 	corba-iiop 	CORBA IIOP
684 	tcp 	corba-iiop-ssl 	CORBA IIOP SSL
684 	udp 	corba-iiop-ssl 	CORBA IIOP SSL
685 	tcp 	mdc-portmapper 	MDC Port Mapper
685 	udp 	mdc-portmapper 	MDC Port Mapper
686 	tcp 	hcp-wismar 	Hardware Control Protocol Wismar
686 	udp 	hcp-wismar 	Hardware Control Protocol Wismar
687 	tcp 	asipregistry 	asipregistry
687 	udp 	asipregistry 	asipregistry
688 	tcp 	realm-rusd 	ApplianceWare managment protocol
688 	udp 	realm-rusd 	ApplianceWare managment protocol
689 	tcp 	nmap 	NMAP
689 	udp 	nmap 	NMAP
690 	tcp 	vatp 	Velneo Application Transfer Protocol
690 	udp 	vatp 	Velneo Application Transfer Protocol
691 	tcp 	msexch-routing 	MS Exchange Routing
691 	udp 	msexch-routing 	MS Exchange Routing
692 	tcp 	hyperwave-isp 	Hyperwave-ISP
692 	udp 	hyperwave-isp 	Hyperwave-ISP
693 	tcp 	connendp 	almanid Connection Endpoint
693 	udp 	connendp 	almanid Connection Endpoint
694 	tcp 	ha-cluster 	ha-cluster
694 	udp 	ha-cluster 	ha-cluster
695 	tcp 	ieee-mms-ssl 	IEEE-MMS-SSL
695 	udp 	ieee-mms-ssl 	IEEE-MMS-SSL
696 	tcp 	rushd 	RUSHD
696 	udp 	rushd 	RUSHD
697 	tcp 	uuidgen 	UUIDGEN
697 	udp 	uuidgen 	UUIDGEN
698 	tcp 	olsr 	OLSR
698 	udp 	olsr 	OLSR
699 	tcp 	accessnetwork 	Access Network
699 	udp 	accessnetwork 	Access Network
700 	tcp 	epp 	Extensible Provisioning Protocol
700 	udp 	epp 	Extensible Provisioning Protocol
701 	tcp 	lmp 	Link Management Protocol (LMP)
701 	udp 	lmp 	Link Management Protocol (LMP)
702 	tcp 	iris-beep 	IRIS over BEEP
702 	udp 	iris-beep 	IRIS over BEEP
703 			Unassigned
704 	tcp 	elcsd 	errlog copy/server daemon
704 	udp 	elcsd 	errlog copy/server daemon
705 	tcp 	agentx 	AgentX
705 	udp 	agentx 	AgentX
706 	tcp 	silc 	SILC
706 	udp 	silc 	SILC
707 	tcp 	borland-dsj 	Borland DSJ
707 	udp 	borland-dsj 	Borland DSJ
708 			Unassigned
709 	tcp 	entrust-kmsh 	Entrust Key Management Service Handler
709 	udp 	entrust-kmsh 	Entrust Key Management Service Handler
710 	tcp 	entrust-ash 	Entrust Administration Service Handler
710 	udp 	entrust-ash 	Entrust Administration Service Handler
711 	tcp 	cisco-tdp 	Cisco TDP
711 	udp 	cisco-tdp 	Cisco TDP
712 	tcp 	tbrpf 	TBRPF
712 	udp 	tbrpf 	TBRPF
713 	tcp 	iris-xpc 	IRIS over XPC
713 	udp 	iris-xpc 	IRIS over XPC
714 	tcp 	iris-xpcs 	IRIS over XPCS
714 	udp 	iris-xpcs 	IRIS over XPCS
715 	tcp 	iris-lwz 	IRIS-LWZ
715 	udp 	iris-lwz 	IRIS-LWZ
716 	udp 	pana 	PANA Messages
717-728 			Unassigned
729 	tcp 	netviewdm1 	IBM NetView DM/6000 Server/Client
729 	udp 	netviewdm1 	IBM NetView DM/6000 Server/Client
730 	tcp 	netviewdm2 	IBM NetView DM/6000 send/tcp
730 	udp 	netviewdm2 	IBM NetView DM/6000 send/tcp
731 	tcp 	netviewdm3 	IBM NetView DM/6000 receive/tcp
731 	udp 	netviewdm3 	IBM NetView DM/6000 receive/tcp
732-740 			Unassigned
741 	tcp 	netgw 	netGW
741 	udp 	netgw 	netGW
742 	tcp 	netrcs 	Network based Rev. Cont. Sys.
742 	udp 	netrcs 	Network based Rev. Cont. Sys.
743 			Unassigned
744 	tcp 	flexlm 	Flexible License Manager
744 	udp 	flexlm 	Flexible License Manager
745-746 			Unassigned
747 	tcp 	fujitsu-dev 	Fujitsu Device Control
747 	udp 	fujitsu-dev 	Fujitsu Device Control
748 	tcp 	ris-cm 	Russell Info Sci Calendar Manager
748 	udp 	ris-cm 	Russell Info Sci Calendar Manager
749 	tcp 	kerberos-adm 	kerberos administration
749 	udp 	kerberos-adm 	kerberos administration
750 	tcp 	rfile 	
750 	udp 	loadav 	
750 	udp 	kerberos-iv 	kerberos version iv
751 	tcp 	pump 	
751 	udp 	pump 	
752 	tcp 	qrh 	
752 	udp 	qrh 	
753 	tcp 	rrh 	
753 	udp 	rrh 	
754 	tcp 	tell 	send
754 	udp 	tell 	send
755-757 			Unassigned
758 	tcp 	nlogin 	
758 	udp 	nlogin 	
759 	tcp 	con 	
759 	udp 	con 	
760 	tcp 	ns 	
760 	udp 	ns 	
761 	tcp 	rxe 	
761 	udp 	rxe 	
762 	tcp 	quotad 	
762 	udp 	quotad 	
763 	tcp 	cycleserv 	
763 	udp 	cycleserv 	
764 	tcp 	omserv 	
764 	udp 	omserv 	
765 	tcp 	webster 	
765 	udp 	webster 	
766 			Unassigned
767 	tcp 	phonebook 	phone
767 	udp 	phonebook 	phone
768 			Unassigned
769 	tcp 	vid 	
769 	udp 	vid 	
770 	tcp 	cadlock 	
770 	udp 	cadlock 	
771 	tcp 	rtip 	
771 	udp 	rtip 	
772 	tcp 	cycleserv2 	
772 	udp 	cycleserv2 	
773 	tcp 	submit 	
773 	udp 	notify 	
774 	tcp 	rpasswd 	
774 	udp 	acmaint-dbd 	replacement for “acmaint_dbd”.
774 	udp 	acmaint_dbd 	
775 	tcp 	entomb 	
775 	udp 	acmaint-transd 	
775 	udp 	acmaint_transd 	
776 	tcp 	wpages 	
776 	udp 	wpages 	
777 	tcp 	multiling-http 	Multiling HTTP
777 	udp 	multiling-http 	Multiling HTTP
778-779 			Unassigned
780 	tcp 	wpgs 	
780 	udp 	wpgs 	
781-785 			Unassigned
786 			Unassigned
787 			Unassigned
788-799 			Unassigned
800 	tcp 	mdbs-daemon 	
800 	tcp 	mdbs_daemon 	
800 	udp 	mdbs-daemon 	
800 	udp 	mdbs_daemon 	
801 	tcp 	device 	
801 	udp 	device 	
802 	tcp 	mbap-s 	Modbus Application Protocol Secure
802 	udp 	mbap-s 	Modbus Application Protocol Secure
803-809 			Unassigned
810 	tcp 	fcp-udp 	FCP
810 	udp 	fcp-udp 	FCP Datagram
811-827 			Unassigned
828 	tcp 	itm-mcell-s 	itm-mcell-s
828 	udp 	itm-mcell-s 	itm-mcell-s
829 	tcp 	pkix-3-ca-ra 	PKIX-3 CA/RA
829 	udp 	pkix-3-ca-ra 	PKIX-3 CA/RA
830 	tcp 	netconf-ssh 	NETCONF over SSH
830 	udp 	netconf-ssh 	NETCONF over SSH
831 	tcp 	netconf-beep 	NETCONF over BEEP
831 	udp 	netconf-beep 	NETCONF over BEEP
832 	tcp 	netconfsoaphttp 	NETCONF for SOAP over HTTPS
832 	udp 	netconfsoaphttp 	NETCONF for SOAP over HTTPS
833 	tcp 	netconfsoapbeep 	NETCONF for SOAP over BEEP
833 	udp 	netconfsoapbeep 	NETCONF for SOAP over BEEP
834-846 			Unassigned
847 	tcp 	dhcp-failover2 	dhcp-failover 2
847 	udp 	dhcp-failover2 	dhcp-failover 2
848 	tcp 	gdoi 	GDOI
848 	udp 	gdoi 	GDOI
849-852 			Unassigned
853 	tcp 	domain-s 	DNS query-response protocol run over TLS/DTLS
853 	udp 	domain-s 	DNS query-response protocol run over TLS/DTLS
854 	tcp 	dlep 	Dynamic Link Exchange Protocol (DLEP)
854 	udp 	dlep 	Dynamic Link Exchange Protocol (DLEP)
855-859 			Unassigned
860 	tcp 	iscsi 	iSCSI
860 	udp 	iscsi 	iSCSI
861 	tcp 	owamp-control 	OWAMP-Control
861 	udp 	owamp-control 	OWAMP-Control
862 	tcp 	twamp-control 	(TWAMP) Control
862 	udp 	twamp-control 	(TWAMP) Control
863-872 			Unassigned
873 	tcp 	rsync 	rsync
873 	udp 	rsync 	rsync
874-885 			Unassigned
886 	tcp 	iclcnet-locate 	ICL coNETion locate server
886 	udp 	iclcnet-locate 	ICL coNETion locate server
887 	tcp 	iclcnet-svinfo 	ICL coNETion server info
IANA assigned this well-formed service name as a replacement for “iclcnet_svinfo”.
887 	tcp 	iclcnet_svinfo 	ICL coNETion server info
887 	udp 	iclcnet-svinfo 	ICL coNETion server info
IANA assigned this well-formed service name as a replacement for “iclcnet_svinfo”.
887 	udp 	iclcnet_svinfo 	ICL coNETion server info
888 	tcp 	accessbuilder 	AccessBuilder
888 	udp 	accessbuilder 	AccessBuilder
888 	tcp 	cddbp 	CD Database Protocol
889-899 			Unassigned
900 	tcp 	omginitialrefs 	OMG Initial Refs
900 	udp 	omginitialrefs 	OMG Initial Refs
901 	tcp 	smpnameres 	SMPNAMERES
901 	udp 	smpnameres 	SMPNAMERES
902 	tcp 	ideafarm-door 	self documenting Telnet Door
902 	udp 	ideafarm-door 	self documenting Door: send 0x00 for info
903 	tcp 	ideafarm-panic 	self documenting Telnet Panic Door
903 	udp 	ideafarm-panic 	self documenting Panic Door: send 0x00 for info
904-909 			Unassigned
910 	tcp 	kink 	Kerberized Internet Negotiation of Keys (KINK)
910 	udp 	kink 	Kerberized Internet Negotiation of Keys (KINK)
911 	tcp 	xact-backup 	xact-backup
911 	udp 	xact-backup 	xact-backup
912 	tcp 	apex-mesh 	APEX relay-relay service
912 	udp 	apex-mesh 	APEX relay-relay service
913 	tcp 	apex-edge 	APEX endpoint-relay service
913 	udp 	apex-edge 	APEX endpoint-relay service
914-952 			Unassigned
953 	tcp 	rndc 	BIND9 remote name daemon controller
953 	udp 		Reserved
954-988 			Unassigned
989 	tcp 	ftps-data 	ftp protocol, data, over TLS/SSL
989 	udp 	ftps-data 	ftp protocol, data, over TLS/SSL
990 	tcp 	ftps 	ftp protocol, control, over TLS/SSL
990 	udp 	ftps 	ftp protocol, control, over TLS/SSL
991 	tcp 	nas 	Netnews Administration System
991 	udp 	nas 	Netnews Administration System
992 	tcp 	telnets 	telnet protocol over TLS/SSL
992 	udp 	telnets 	telnet protocol over TLS/SSL
993 	tcp 	imaps 	imap4 protocol over TLS/SSL
993 	udp 	imaps 	imap4 protocol over TLS/SSL
994 	tcp 		Reserved
994 	udp 		Reserved
995 	tcp 	pop3s 	pop3 protocol over TLS/SSL (was spop3)
995 	udp 	pop3s 	pop3 protocol over TLS/SSL (was spop3)
996 	tcp 	vsinet 	vsinet
996 	udp 	vsinet 	vsinet
997 	tcp 	maitrd 	
997 	udp 	maitrd 	
998 	tcp 	busboy 	
998 	udp 	puparp 	
999 	tcp 	garcon 	
999 	udp 	applix 	Applix ac
999 	tcp 	puprouter 	
999 	udp 	puprouter 	
1000 	tcp 	cadlock2 	
1000 	udp 	cadlock2 	
1001 	tcp 	webpush 	HTTP Web Push
1001 	udp 		Reserved
1002-1007 		Unassigned
1008 	udp 		Possibly used by Sun Solaris????
1009 			Unassigned
1010 	tcp 	surf 	surf
1010 	udp 	surf 	surf
1011-1020 		Reserved
1021 	tcp 	exp1 	RFC3692-style Experiment 1
1021 	udp 	exp1 	RFC3692-style Experiment 1
1021 	sctp 	exp1 	RFC3692-style Experiment 1
1021 	dccp 	exp1 	RFC3692-style Experiment 1
1022 	tcp 	exp2 	RFC3692-style Experiment 2
1022 	udp 	exp2 	RFC3692-style Experiment 2
1022 	sctp 	exp2 	RFC3692-style Experiment 2
1022 	dccp 	exp2 	RFC3692-style Experiment 2
1023 	tcp 		Reserved
1023 	udp 		Reserved
1024 	tcp 		Reserved
1024 	udp 		Reserved
1025 	tcp 	blackjack 	network blackjack
1025 	udp 	blackjack 	network blackjack
1026 	tcp 	cap 	Calendar Access Protocol
1026 	udp 	cap 	Calendar Access Protocol
1027 	udp 	6a44 	IPv6 Behind NAT44 CPEs
1027 	tcp 		Reserved
1028 			Deprecated
1029 	tcp 	solid-mux 	Solid Mux Server
1029 	udp 	solid-mux 	Solid Mux Server
1030 			Reserved
1031 			Reserved
1032 			Reserved
1033 	tcp 	netinfo-local 	local netinfo port
1033 	udp 	netinfo-local 	local netinfo port
1034 	tcp 	activesync 	ActiveSync Notifications
1034 	udp 	activesync 	ActiveSync Notifications
1035 	tcp 	mxxrlogin 	MX-XR RPC
1035 	udp 	mxxrlogin 	MX-XR RPC
1036 	tcp 	nsstp 	Nebula Secure Segment Transfer Protocol
1036 	udp 	nsstp 	Nebula Secure Segment Transfer Protocol
1037 	tcp 	ams 	AMS
1037 	udp 	ams 	AMS
1038 	tcp 	mtqp 	Message Tracking Query Protocol
1038 	udp 	mtqp 	Message Tracking Query Protocol
1039 	tcp 	sbl 	Streamlined Blackhole
1039 	udp 	sbl 	Streamlined Blackhole
1040 	tcp 	netarx 	Netarx Netcare
1040 	udp 	netarx 	Netarx Netcare
1041 	tcp 	danf-ak2 	AK2 Product
1041 	udp 	danf-ak2 	AK2 Product
1042 	tcp 	afrog 	Subnet Roaming
1042 	udp 	afrog 	Subnet Roaming
1043 	tcp 	boinc-client 	BOINC Client Control
1043 	udp 	boinc-client 	BOINC Client Control
1044 	tcp 	dcutility 	Dev Consortium Utility
1044 	udp 	dcutility 	Dev Consortium Utility
1045 	tcp 	fpitp 	Fingerprint Image Transfer Protocol
1045 	udp 	fpitp 	Fingerprint Image Transfer Protocol
1046 	tcp 	wfremotertm 	WebFilter Remote Monitor
1046 	udp 	wfremotertm 	WebFilter Remote Monitor
1047 	tcp 	neod1 	Sun’s NEO Object Request Broker
1047 	udp 	neod1 	Sun’s NEO Object Request Broker
1048 	tcp 	neod2 	Sun’s NEO Object Request Broker
1048 	udp 	neod2 	Sun’s NEO Object Request Broker
1049 	tcp 	td-postman 	Tobit David Postman VPMN
1049 	udp 	td-postman 	Tobit David Postman VPMN
1050 	tcp 	cma 	CORBA Management Agent
1050 	udp 	cma 	CORBA Management Agent
1051 	tcp 	optima-vnet 	Optima VNET
1051 	udp 	optima-vnet 	Optima VNET
1052 	tcp 	ddt 	Dynamic DNS Tools
1052 	udp 	ddt 	Dynamic DNS Tools
1053 	tcp 	remote-as 	Remote Assistant (RA)
1053 	udp 	remote-as 	Remote Assistant (RA)
1054 	tcp 	brvread 	BRVREAD
1054 	udp 	brvread 	BRVREAD
1055 	tcp 	ansyslmd 	ANSYS – License Manager
1055 	udp 	ansyslmd 	ANSYS – License Manager
1056 	tcp 	vfo 	VFO
1056 	udp 	vfo 	VFO
1057 	tcp 	startron 	STARTRON
1057 	udp 	startron 	STARTRON
1058 	tcp 	nim 	nim
1058 	udp 	nim 	nim
1059 	tcp 	nimreg 	nimreg
1059 	udp 	nimreg 	nimreg
1060 	tcp 	polestar 	POLESTAR
1060 	udp 	polestar 	POLESTAR
1061 	tcp 	kiosk 	KIOSK
1061 	udp 	kiosk 	KIOSK
1062 	tcp 	veracity 	Veracity
1062 	udp 	veracity 	Veracity
1063 	tcp 	kyoceranetdev 	KyoceraNetDev
1063 	udp 	kyoceranetdev 	KyoceraNetDev
1064 	tcp 	jstel 	JSTEL
1064 	udp 	jstel 	JSTEL
1065 	tcp 	syscomlan 	SYSCOMLAN
1065 	udp 	syscomlan 	SYSCOMLAN
1066 	tcp 	fpo-fns 	FPO-FNS
1066 	udp 	fpo-fns 	FPO-FNS
1067 	tcp 	instl-boots 	Installation Bootstrap Proto. Serv.
IANA assigned this well-formed service name as a replacement for “instl_boots”.
1067 	tcp 	instl_boots 	Installation Bootstrap Proto. Serv.
1067 	udp 	instl-boots 	Installation Bootstrap Proto. Serv.
IANA assigned this well-formed service name as a replacement for “instl_boots”.
1067 	udp 	instl_boots 	Installation Bootstrap Proto. Serv.
1068 	tcp 	instl-bootc 	Installation Bootstrap Proto. Cli.
IANA assigned this well-formed service name as a replacement for “instl_bootc”.
1068 	tcp 	instl_bootc 	Installation Bootstrap Proto. Cli.
1068 	udp 	instl-bootc 	Installation Bootstrap Proto. Cli.
IANA assigned this well-formed service name as a replacement for “instl_bootc”.
1068 	udp 	instl_bootc 	Installation Bootstrap Proto. Cli.
1069 	tcp 	cognex-insight 	COGNEX-INSIGHT
1069 	udp 	cognex-insight 	COGNEX-INSIGHT
1070 	tcp 	gmrupdateserv 	GMRUpdateSERV
1070 	udp 	gmrupdateserv 	GMRUpdateSERV
1071 	tcp 	bsquare-voip 	BSQUARE-VOIP
1071 	udp 	bsquare-voip 	BSQUARE-VOIP
1072 	tcp 	cardax 	CARDAX
1072 	udp 	cardax 	CARDAX
1073 	tcp 	bridgecontrol 	Bridge Control
1073 	udp 	bridgecontrol 	Bridge Control
1074 	tcp 	warmspotMgmt 	Warmspot Management Protocol
1074 	udp 	warmspotMgmt 	Warmspot Management Protocol
1075 	tcp 	rdrmshc 	RDRMSHC
1075 	udp 	rdrmshc 	RDRMSHC
1076 	tcp 	dab-sti-c 	DAB STI-C
1076 	udp 	dab-sti-c 	DAB STI-C
1077 	tcp 	imgames 	IMGames
1077 	udp 	imgames 	IMGames
1078 	tcp 	avocent-proxy 	Avocent Proxy Protocol
1078 	udp 	avocent-proxy 	Avocent Proxy Protocol
1079 	tcp 	asprovatalk 	ASPROVATalk
1079 	udp 	asprovatalk 	ASPROVATalk
1080 	tcp 	socks 	Socks
1080 	udp 	socks 	Socks
1081 	tcp 	pvuniwien 	PVUNIWIEN
1081 	udp 	pvuniwien 	PVUNIWIEN
1082 	tcp 	amt-esd-prot 	AMT-ESD-PROT
1082 	udp 	amt-esd-prot 	AMT-ESD-PROT
1083 	tcp 	ansoft-lm-1 	Anasoft License Manager
1083 	udp 	ansoft-lm-1 	Anasoft License Manager
1084 	tcp 	ansoft-lm-2 	Anasoft License Manager
1084 	udp 	ansoft-lm-2 	Anasoft License Manager
1085 	tcp 	webobjects 	Web Objects
1085 	udp 	webobjects 	Web Objects
1086 	tcp 	cplscrambler-lg 	CPL Scrambler Logging
1086 	udp 	cplscrambler-lg 	CPL Scrambler Logging
1087 	tcp 	cplscrambler-in 	CPL Scrambler Internal
1087 	udp 	cplscrambler-in 	CPL Scrambler Internal
1088 	tcp 	cplscrambler-al 	CPL Scrambler Alarm Log
1088 	udp 	cplscrambler-al 	CPL Scrambler Alarm Log
1089 	tcp 	ff-annunc 	FF Annunciation
1089 	udp 	ff-annunc 	FF Annunciation
1090 	tcp 	ff-fms 	FF Fieldbus Message Specification
1090 	udp 	ff-fms 	FF Fieldbus Message Specification
1091 	tcp 	ff-sm 	FF System Management
1091 	udp 	ff-sm 	FF System Management
1092 	tcp 	obrpd 	Open Business Reporting Protocol
1092 	udp 	obrpd 	Open Business Reporting Protocol
1093 	tcp 	proofd 	PROOFD
1093 	udp 	proofd 	PROOFD
1094 	tcp 	rootd 	ROOTD
1094 	udp 	rootd 	ROOTD
1095 	tcp 	nicelink 	NICELink
1095 	udp 	nicelink 	NICELink
1096 	tcp 	cnrprotocol 	Common Name Resolution Protocol
1096 	udp 	cnrprotocol 	Common Name Resolution Protocol
1097 	tcp 	sunclustermgr 	Sun Cluster Manager
1097 	udp 	sunclustermgr 	Sun Cluster Manager
1098 	tcp 	rmiactivation 	RMI Activation
1098 	udp 	rmiactivation 	RMI Activation
1099 	tcp 	rmiregistry 	RMI Registry
1099 	udp 	rmiregistry 	RMI Registry
1100 	tcp 	mctp 	MCTP
1100 	udp 	mctp 	MCTP
1101 	tcp 	pt2-discover 	PT2-DISCOVER
1101 	udp 	pt2-discover 	PT2-DISCOVER
1102 	tcp 	adobeserver-1 	ADOBE SERVER 1
1102 	udp 	adobeserver-1 	ADOBE SERVER 1
1103 	tcp 	adobeserver-2 	ADOBE SERVER 2
1103 	udp 	adobeserver-2 	ADOBE SERVER 2
1104 	tcp 	xrl 	XRL
1104 	udp 	xrl 	XRL
1105 	tcp 	ftranhc 	FTRANHC
1105 	udp 	ftranhc 	FTRANHC
1106 	tcp 	isoipsigport-1 	ISOIPSIGPORT-1
1106 	udp 	isoipsigport-1 	ISOIPSIGPORT-1
1107 	tcp 	isoipsigport-2 	ISOIPSIGPORT-2
1107 	udp 	isoipsigport-2 	ISOIPSIGPORT-2
1108 	tcp 	ratio-adp 	ratio-adp
1108 	udp 	ratio-adp 	ratio-adp
1109 			Reserved – IANA
1110 	tcp 	webadmstart 	Start web admin server
1110 	udp 	nfsd-keepalive 	Client status info
1111 	tcp 	lmsocialserver 	LM Social Server
1111 	udp 	lmsocialserver 	LM Social Server
1112 	tcp 	icp 	Intelligent Communication Protocol
1112 	udp 	icp 	Intelligent Communication Protocol
1113 	tcp 	ltp-deepspace 	Licklider Transmission Protocol
1113 	udp 	ltp-deepspace 	Licklider Transmission Protocol
1113 	dccp 	ltp-deepspace 	Licklider Transmission Protocol
1114 	tcp 	mini-sql 	Mini SQL
1114 	udp 	mini-sql 	Mini SQL
1115 	tcp 	ardus-trns 	ARDUS Transfer
1115 	udp 	ardus-trns 	ARDUS Transfer
1116 	tcp 	ardus-cntl 	ARDUS Control
1116 	udp 	ardus-cntl 	ARDUS Control
1117 	tcp 	ardus-mtrns 	ARDUS Multicast Transfer
1117 	udp 	ardus-mtrns 	ARDUS Multicast Transfer
1118 	tcp 	sacred 	SACRED
1118 	udp 	sacred 	SACRED
1119 	tcp 	bnetgame 	Battle.net Chat/Game Protocol
1119 	udp 	bnetgame 	Battle.net Chat/Game Protocol
1120 	tcp 	bnetfile 	Battle.net File Transfer Protocol
1120 	udp 	bnetfile 	Battle.net File Transfer Protocol
1121 	tcp 	rmpp 	Datalode RMPP
1121 	udp 	rmpp 	Datalode RMPP
1122 	tcp 	availant-mgr 	availant-mgr
1122 	udp 	availant-mgr 	availant-mgr
1123 	tcp 	murray 	Murray
1123 	udp 	murray 	Murray
1124 	tcp 	hpvmmcontrol 	HP VMM Control
1124 	udp 	hpvmmcontrol 	HP VMM Control
1125 	tcp 	hpvmmagent 	HP VMM Agent
1125 	udp 	hpvmmagent 	HP VMM Agent
1126 	tcp 	hpvmmdata 	HP VMM Agent
1126 	udp 	hpvmmdata 	HP VMM Agent
1127 	tcp 	kwdb-commn 	KWDB Remote Communication
1127 	udp 	kwdb-commn 	KWDB Remote Communication
1128 	tcp 	saphostctrl 	SAPHostControl over SOAP/HTTP
1128 	udp 	saphostctrl 	SAPHostControl over SOAP/HTTP
1129 	tcp 	saphostctrls 	SAPHostControl over SOAP/HTTPS
1129 	udp 	saphostctrls 	SAPHostControl over SOAP/HTTPS
1130 	tcp 	casp 	CAC App Service Protocol
1130 	udp 	casp 	CAC App Service Protocol
1131 	tcp 	caspssl 	CAC App Service Protocol Encripted
1131 	udp 	caspssl 	CAC App Service Protocol Encripted
1132 	tcp 	kvm-via-ip 	KVM-via-IP Management Service
1132 	udp 	kvm-via-ip 	KVM-via-IP Management Service
1133 	tcp 	dfn 	Data Flow Network
1133 	udp 	dfn 	Data Flow Network
1134 	tcp 	aplx 	MicroAPL APLX
1134 	udp 	aplx 	MicroAPL APLX
1135 	tcp 	omnivision 	OmniVision Communication Service
1135 	udp 	omnivision 	OmniVision Communication Service
1136 	tcp 	hhb-gateway 	HHB Gateway Control
1136 	udp 	hhb-gateway 	HHB Gateway Control
1137 	tcp 	trim 	TRIM Workgroup Service
1137 	udp 	trim 	TRIM Workgroup Service
1138 	tcp 	encrypted-admin 	encrypted admin requests
IANA assigned this well-formed service name as a replacement for “encrypted_admin”.
1138 	tcp 	encrypted_admin 	encrypted admin requests
1138 	udp 	encrypted-admin 	encrypted admin requests
IANA assigned this well-formed service name as a replacement for “encrypted_admin”.
1138 	udp 	encrypted_admin 	encrypted admin requests
1139 	tcp 	evm 	Enterprise Virtual Manager
1139 	udp 	evm 	Enterprise Virtual Manager
1140 	tcp 	autonoc 	AutoNOC Network Operations Protocol
1140 	udp 	autonoc 	AutoNOC Network Operations Protocol
1141 	tcp 	mxomss 	User Message Service
1141 	udp 	mxomss 	User Message Service
1142 	tcp 	edtools 	User Discovery Service
1142 	udp 	edtools 	User Discovery Service
1143 	tcp 	imyx 	Infomatryx Exchange
1143 	udp 	imyx 	Infomatryx Exchange
1144 	tcp 	fuscript 	Fusion Script
1144 	udp 	fuscript 	Fusion Script
1145 	tcp 	x9-icue 	X9 iCue Show Control
1145 	udp 	x9-icue 	X9 iCue Show Control
1146 	tcp 	audit-transfer 	audit transfer
1146 	udp 	audit-transfer 	audit transfer
1147 	tcp 	capioverlan 	CAPIoverLAN
1147 	udp 	capioverlan 	CAPIoverLAN
1148 	tcp 	elfiq-repl 	Elfiq Replication Service
1148 	udp 	elfiq-repl 	Elfiq Replication Service
1149 	tcp 	bvtsonar 	BlueView Sonar Service
1149 	udp 	bvtsonar 	BlueView Sonar Service
1150 	tcp 	blaze 	Blaze File Server
1150 	udp 	blaze 	Blaze File Server
1151 	tcp 	unizensus 	Unizensus Login Server
1151 	udp 	unizensus 	Unizensus Login Server
1152 	tcp 	winpoplanmess 	Winpopup LAN Messenger
1152 	udp 	winpoplanmess 	Winpopup LAN Messenger
1153 	tcp 	c1222-acse 	ANSI C12.22 Port
1153 	udp 	c1222-acse 	ANSI C12.22 Port
1154 	tcp 	resacommunity 	Community Service
1154 	udp 	resacommunity 	Community Service
1155 	tcp 	nfa 	Network File Access
1155 	udp 	nfa 	Network File Access
1156 	tcp 	iascontrol-oms 	iasControl OMS
1156 	udp 	iascontrol-oms 	iasControl OMS
1157 	tcp 	iascontrol 	Oracle iASControl
1157 	udp 	iascontrol 	Oracle iASControl
1158 	tcp 	dbcontrol-oms 	dbControl OMS
1158 	udp 	dbcontrol-oms 	dbControl OMS
1159 	tcp 	oracle-oms 	Oracle OMS
1159 	udp 	oracle-oms 	Oracle OMS
1160 	tcp 	olsv 	DB Lite Mult-User Server
1160 	udp 	olsv 	DB Lite Mult-User Server
1161 	tcp 	health-polling 	Health Polling
1161 	udp 	health-polling 	Health Polling
1162 	tcp 	health-trap 	Health Trap
1162 	udp 	health-trap 	Health Trap
1163 	tcp 	sddp 	SmartDialer Data Protocol
1163 	udp 	sddp 	SmartDialer Data Protocol
1164 	tcp 	qsm-proxy 	QSM Proxy Service
1164 	udp 	qsm-proxy 	QSM Proxy Service
1165 	tcp 	qsm-gui 	QSM GUI Service
1165 	udp 	qsm-gui 	QSM GUI Service
1166 	tcp 	qsm-remote 	QSM RemoteExec
1166 	udp 	qsm-remote 	QSM RemoteExec
1167 	tcp 	cisco-ipsla 	Cisco IP SLAs Control Protocol
1167 	udp 	cisco-ipsla 	Cisco IP SLAs Control Protocol
1167 	sctp 	cisco-ipsla 	Cisco IP SLAs Control Protocol
1168 	tcp 	vchat 	VChat Conference Service
1168 	udp 	vchat 	VChat Conference Service
1169 	tcp 	tripwire 	TRIPWIRE
1169 	udp 	tripwire 	TRIPWIRE
1170 	tcp 	atc-lm 	AT+C License Manager
1170 	udp 	atc-lm 	AT+C License Manager
1171 	tcp 	atc-appserver 	AT+C FmiApplicationServer
1171 	udp 	atc-appserver 	AT+C FmiApplicationServer
1172 	tcp 	dnap 	DNA Protocol
1172 	udp 	dnap 	DNA Protocol
1173 	tcp 	d-cinema-rrp 	D-Cinema Request-Response
1173 	udp 	d-cinema-rrp 	D-Cinema Request-Response
1174 	tcp 	fnet-remote-ui 	FlashNet Remote Admin
1174 	udp 	fnet-remote-ui 	FlashNet Remote Admin
1175 	tcp 	dossier 	Dossier Server
1175 	udp 	dossier 	Dossier Server
1176 	tcp 	indigo-server 	Indigo Home Server
1176 	udp 	indigo-server 	Indigo Home Server
1177 	tcp 	dkmessenger 	DKMessenger Protocol
1177 	udp 	dkmessenger 	DKMessenger Protocol
1178 	tcp 	sgi-storman 	SGI Storage Manager
1178 	udp 	sgi-storman 	SGI Storage Manager
1179 	tcp 	b2n 	Backup To Neighbor
1179 	udp 	b2n 	Backup To Neighbor
1180 	tcp 	mc-client 	Millicent Client Proxy
1180 	udp 	mc-client 	Millicent Client Proxy
1181 	tcp 	3comnetman 	3Com Net Management
1181 	udp 	3comnetman 	3Com Net Management
1182 	tcp 	accelenet 	AcceleNet Control
1182 	udp 	accelenet-data 	AcceleNet Data
1183 	tcp 	llsurfup-http 	LL Surfup HTTP
1183 	udp 	llsurfup-http 	LL Surfup HTTP
1184 	tcp 	llsurfup-https 	LL Surfup HTTPS
1184 	udp 	llsurfup-https 	LL Surfup HTTPS
1185 	tcp 	catchpole 	Catchpole port
1185 	udp 	catchpole 	Catchpole port
1186 	tcp 	mysql-cluster 	MySQL Cluster Manager
1186 	udp 	mysql-cluster 	MySQL Cluster Manager
1187 	tcp 	alias 	Alias Service
1187 	udp 	alias 	Alias Service
1188 	tcp 	hp-webadmin 	HP Web Admin
1188 	udp 	hp-webadmin 	HP Web Admin
1189 	tcp 	unet 	Unet Connection
1189 	udp 	unet 	Unet Connection
1190 	tcp 	commlinx-avl 	CommLinx GPS / AVL System
1190 	udp 	commlinx-avl 	CommLinx GPS / AVL System
1191 	tcp 	gpfs 	General Parallel File System
1191 	udp 	gpfs 	General Parallel File System
1192 	tcp 	caids-sensor 	caids sensors channel
1192 	udp 	caids-sensor 	caids sensors channel
1193 	tcp 	fiveacross 	Five Across Server
1193 	udp 	fiveacross 	Five Across Server
1194 	tcp 	openvpn 	OpenVPN
1194 	udp 	openvpn 	OpenVPN
1195 	tcp 	rsf-1 	RSF-1 clustering
1195 	udp 	rsf-1 	RSF-1 clustering
1196 	tcp 	netmagic 	Network Magic
1196 	udp 	netmagic 	Network Magic
1197 	tcp 	carrius-rshell 	Carrius Remote Access
1197 	udp 	carrius-rshell 	Carrius Remote Access
1198 	tcp 	cajo-discovery 	cajo reference discovery
1198 	udp 	cajo-discovery 	cajo reference discovery
1199 	tcp 	dmidi 	DMIDI
1199 	udp 	dmidi 	DMIDI
1200 	tcp 	scol 	SCOL
1200 	udp 	scol 	SCOL
1201 	tcp 	nucleus-sand 	Nucleus Sand Database Server
1201 	udp 	nucleus-sand 	Nucleus Sand Database Server
1202 	tcp 	caiccipc 	caiccipc
1202 	udp 	caiccipc 	caiccipc
1203 	tcp 	ssslic-mgr 	License Validation
1203 	udp 	ssslic-mgr 	License Validation
1204 	tcp 	ssslog-mgr 	Log Request Listener
1204 	udp 	ssslog-mgr 	Log Request Listener
1205 	tcp 	accord-mgc 	Accord-MGC
1205 	udp 	accord-mgc 	Accord-MGC
1206 	tcp 	anthony-data 	Anthony Data
1206 	udp 	anthony-data 	Anthony Data
1207 	tcp 	metasage 	MetaSage
1207 	udp 	metasage 	MetaSage
1208 	tcp 	seagull-ais 	SEAGULL AIS
1208 	udp 	seagull-ais 	SEAGULL AIS
1209 	tcp 	ipcd3 	IPCD3
1209 	udp 	ipcd3 	IPCD3
1210 	tcp 	eoss 	EOSS
1210 	udp 	eoss 	EOSS
1211 	tcp 	groove-dpp 	Groove DPP
1211 	udp 	groove-dpp 	Groove DPP
1212 	tcp 	lupa 	lupa
1212 	udp 	lupa 	lupa
1213 	tcp 	mpc-lifenet 	Medtronic/Physio-Control LIFENET
1213 	udp 	mpc-lifenet 	Medtronic/Physio-Control LIFENET
1214 	tcp 	kazaa 	KAZAA
1214 	udp 	kazaa 	KAZAA
1215 	tcp 	scanstat-1 	scanSTAT 1.0
1215 	udp 	scanstat-1 	scanSTAT 1.0
1216 	tcp 	etebac5 	ETEBAC 5
1216 	udp 	etebac5 	ETEBAC 5
1217 	tcp 	hpss-ndapi 	HPSS NonDCE Gateway
1217 	udp 	hpss-ndapi 	HPSS NonDCE Gateway
1218 	tcp 	aeroflight-ads 	AeroFlight-ADs
1218 	udp 	aeroflight-ads 	AeroFlight-ADs
1219 	tcp 	aeroflight-ret 	AeroFlight-Ret
1219 	udp 	aeroflight-ret 	AeroFlight-Ret
1220 	tcp 	qt-serveradmin 	QT SERVER ADMIN
1220 	udp 	qt-serveradmin 	QT SERVER ADMIN
1221 	tcp 	sweetware-apps 	SweetWARE Apps
1221 	udp 	sweetware-apps 	SweetWARE Apps
1222 	tcp 	nerv 	SNI R&D network
1222 	udp 	nerv 	SNI R&D network
1223 	tcp 	tgp 	TrulyGlobal Protocol
1223 	udp 	tgp 	TrulyGlobal Protocol
1224 	tcp 	vpnz 	VPNz
1224 	udp 	vpnz 	VPNz
1225 	tcp 	slinkysearch 	SLINKYSEARCH
1225 	udp 	slinkysearch 	SLINKYSEARCH
1226 	tcp 	stgxfws 	STGXFWS
1226 	udp 	stgxfws 	STGXFWS
1227 	tcp 	dns2go 	DNS2Go
1227 	udp 	dns2go 	DNS2Go
1228 	tcp 	florence 	FLORENCE
1228 	udp 	florence 	FLORENCE
1229 	tcp 	zented 	ZENworks Tiered Electronic Distribution
1229 	udp 	zented 	ZENworks Tiered Electronic Distribution
1230 	tcp 	periscope 	Periscope
1230 	udp 	periscope 	Periscope
1231 	tcp 	menandmice-lpm 	menandmice-lpm
1231 	udp 	menandmice-lpm 	menandmice-lpm
1232 	tcp 	first-defense 	Remote systems monitoring
1232 	udp 	first-defense 	Remote systems monitoring
1233 	tcp 	univ-appserver 	Universal App Server
1233 	udp 	univ-appserver 	Universal App Server
1234 	tcp 	search-agent 	Infoseek Search Agent
1234 	udp 	search-agent 	Infoseek Search Agent
1235 	tcp 	mosaicsyssvc1 	mosaicsyssvc1
1235 	udp 	mosaicsyssvc1 	mosaicsyssvc1
1236 	tcp 	bvcontrol 	bvcontrol
1236 	udp 	bvcontrol 	bvcontrol
1237 	tcp 	tsdos390 	tsdos390
1237 	udp 	tsdos390 	tsdos390
1238 	tcp 	hacl-qs 	hacl-qs
1238 	udp 	hacl-qs 	hacl-qs
1239 	tcp 	nmsd 	NMSD
1239 	udp 	nmsd 	NMSD
1240 	tcp 	instantia 	Instantia
1240 	udp 	instantia 	Instantia
1241 	tcp 	nessus 	nessus
1241 	udp 	nessus 	nessus
1242 	tcp 	nmasoverip 	NMAS over IP
1242 	udp 	nmasoverip 	NMAS over IP
1243 	tcp 	serialgateway 	SerialGateway
1243 	udp 	serialgateway 	SerialGateway
1244 	tcp 	isbconference1 	isbconference1
1244 	udp 	isbconference1 	isbconference1
1245 	tcp 	isbconference2 	isbconference2
1245 	udp 	isbconference2 	isbconference2
1246 	tcp 	payrouter 	payrouter
1246 	udp 	payrouter 	payrouter
1247 	tcp 	visionpyramid 	VisionPyramid
1247 	udp 	visionpyramid 	VisionPyramid
1248 	tcp 	hermes 	hermes
1248 	udp 	hermes 	hermes
1249 	tcp 	mesavistaco 	Mesa Vista Co
1249 	udp 	mesavistaco 	Mesa Vista Co
1250 	tcp 	swldy-sias 	swldy-sias
1250 	udp 	swldy-sias 	swldy-sias
1251 	tcp 	servergraph 	servergraph
1251 	udp 	servergraph 	servergraph
1252 	tcp 	bspne-pcc 	bspne-pcc
1252 	udp 	bspne-pcc 	bspne-pcc
1253 	tcp 	q55-pcc 	q55-pcc
1253 	udp 	q55-pcc 	q55-pcc
1254 	tcp 	de-noc 	de-noc
1254 	udp 	de-noc 	de-noc
1255 	tcp 	de-cache-query 	de-cache-query
1255 	udp 	de-cache-query 	de-cache-query
1256 	tcp 	de-server 	de-server
1256 	udp 	de-server 	de-server
1257 	tcp 	shockwave2 	Shockwave 2
1257 	udp 	shockwave2 	Shockwave 2
1258 	tcp 	opennl 	Open Network Library
1258 	udp 	opennl 	Open Network Library
1259 	tcp 	opennl-voice 	Open Network Library Voice
1259 	udp 	opennl-voice 	Open Network Library Voice
1260 	tcp 	ibm-ssd 	ibm-ssd
1260 	udp 	ibm-ssd 	ibm-ssd
1261 	tcp 	mpshrsv 	mpshrsv
1261 	udp 	mpshrsv 	mpshrsv
1262 	tcp 	qnts-orb 	QNTS-ORB
1262 	udp 	qnts-orb 	QNTS-ORB
1263 	tcp 	dka 	dka
1263 	udp 	dka 	dka
1264 	tcp 	prat 	PRAT
1264 	udp 	prat 	PRAT
1265 	tcp 	dssiapi 	DSSIAPI
1265 	udp 	dssiapi 	DSSIAPI
1266 	tcp 	dellpwrappks 	DELLPWRAPPKS
1266 	udp 	dellpwrappks 	DELLPWRAPPKS
1267 	tcp 	epc 	eTrust Policy Compliance
1267 	udp 	epc 	eTrust Policy Compliance
1268 	tcp 	propel-msgsys 	PROPEL-MSGSYS
1268 	udp 	propel-msgsys 	PROPEL-MSGSYS
1269 	tcp 	watilapp 	WATiLaPP
1269 	udp 	watilapp 	WATiLaPP
1270 	tcp 	opsmgr 	Microsoft Operations Manager
1270 	udp 	opsmgr 	Microsoft Operations Manager
1271 	tcp 	excw 	eXcW
1271 	udp 	excw 	eXcW
1272 	tcp 	cspmlockmgr 	CSPMLockMgr
1272 	udp 	cspmlockmgr 	CSPMLockMgr
1273 	tcp 	emc-gateway 	EMC-Gateway
1273 	udp 	emc-gateway 	EMC-Gateway
1274 	tcp 	t1distproc 	t1distproc
1274 	udp 	t1distproc 	t1distproc
1275 	tcp 	ivcollector 	ivcollector
1275 	udp 	ivcollector 	ivcollector
1276 	tcp 		Reserved
1276 	udp 		Reserved
1277 	tcp 	miva-mqs 	mqs
1277 	udp 	miva-mqs 	mqs
1278 	tcp 	dellwebadmin-1 	Dell Web Admin 1
1278 	udp 	dellwebadmin-1 	Dell Web Admin 1
1279 	tcp 	dellwebadmin-2 	Dell Web Admin 2
1279 	udp 	dellwebadmin-2 	Dell Web Admin 2
1280 	tcp 	pictrography 	Pictrography
1280 	udp 	pictrography 	Pictrography
1281 	tcp 	healthd 	healthd
1281 	udp 	healthd 	healthd
1282 	tcp 	emperion 	Emperion
1282 	udp 	emperion 	Emperion
1283 	tcp 	productinfo 	Product Information
1283 	udp 	productinfo 	Product Information
1284 	tcp 	iee-qfx 	IEE-QFX
1284 	udp 	iee-qfx 	IEE-QFX
1285 	tcp 	neoiface 	neoiface
1285 	udp 	neoiface 	neoiface
1286 	tcp 	netuitive 	netuitive
1286 	udp 	netuitive 	netuitive
1287 	tcp 	routematch 	RouteMatch Com
1287 	udp 	routematch 	RouteMatch Com
1288 	tcp 	navbuddy 	NavBuddy
1288 	udp 	navbuddy 	NavBuddy
1289 	tcp 	jwalkserver 	JWalkServer
1289 	udp 	jwalkserver 	JWalkServer
1290 	tcp 	winjaserver 	WinJaServer
1290 	udp 	winjaserver 	WinJaServer
1291 	tcp 	seagulllms 	SEAGULLLMS
1291 	udp 	seagulllms 	SEAGULLLMS
1292 	tcp 	dsdn 	dsdn
1292 	udp 	dsdn 	dsdn
1293 	tcp 	pkt-krb-ipsec 	PKT-KRB-IPSec
1293 	udp 	pkt-krb-ipsec 	PKT-KRB-IPSec
1294 	tcp 	cmmdriver 	CMMdriver
1294 	udp 	cmmdriver 	CMMdriver
1295 	tcp 	ehtp 	End-by-Hop Transmission Protocol
1295 	udp 	ehtp 	End-by-Hop Transmission Protocol
1296 	tcp 	dproxy 	dproxy
1296 	udp 	dproxy 	dproxy
1297 	tcp 	sdproxy 	sdproxy
1297 	udp 	sdproxy 	sdproxy
1298 	tcp 	lpcp 	lpcp
1298 	udp 	lpcp 	lpcp
1299 	tcp 	hp-sci 	hp-sci
1299 	udp 	hp-sci 	hp-sci
1300 	tcp 	h323hostcallsc 	H.323 Secure Call Control Signalling
1300 	udp 	h323hostcallsc 	H.323 Secure Call Control Signalling
1301 	tcp 	ci3-software-1 	CI3-Software-1
1301 	udp 	ci3-software-1 	CI3-Software-1
1302 	tcp 	ci3-software-2 	CI3-Software-2
1302 	udp 	ci3-software-2 	CI3-Software-2
1303 	tcp 	sftsrv 	sftsrv
1303 	udp 	sftsrv 	sftsrv
1304 	tcp 	boomerang 	Boomerang
1304 	udp 	boomerang 	Boomerang
1305 	tcp 	pe-mike 	pe-mike
1305 	udp 	pe-mike 	pe-mike
1306 	tcp 	re-conn-proto 	RE-Conn-Proto
1306 	udp 	re-conn-proto 	RE-Conn-Proto
1307 	tcp 	pacmand 	Pacmand
1307 	udp 	pacmand 	Pacmand
1308 	tcp 	odsi 	Optical Domain Service Interconnect (ODSI)
1308 	udp 	odsi 	Optical Domain Service Interconnect (ODSI)
1309 	tcp 	jtag-server 	JTAG server
1309 	udp 	jtag-server 	JTAG server
1310 	tcp 	husky 	Husky
1310 	udp 	husky 	Husky
1311 	tcp 	rxmon 	RxMon
1311 	udp 	rxmon 	RxMon
1312 	tcp 	sti-envision 	STI Envision
1312 	udp 	sti-envision 	STI Envision
1313 	tcp 	bmc-patroldb 	BMC_PATROLDB
IANA assigned this well-formed service name as a replacement for “bmc_patroldb”.
1313 	tcp 	bmc_patroldb 	BMC_PATROLDB
1313 	udp 	bmc-patroldb 	BMC_PATROLDB
IANA assigned this well-formed service name as a replacement for “bmc_patroldb”.
1313 	udp 	bmc_patroldb 	BMC_PATROLDB
1314 	tcp 	pdps 	Photoscript Distributed Printing System
1314 	udp 	pdps 	Photoscript Distributed Printing System
1315 	tcp 	els 	E.L.S., Event Listener Service
1315 	udp 	els 	E.L.S., Event Listener Service
1316 	tcp 	exbit-escp 	Exbit-ESCP
1316 	udp 	exbit-escp 	Exbit-ESCP
1317 	tcp 	vrts-ipcserver 	vrts-ipcserver
1317 	udp 	vrts-ipcserver 	vrts-ipcserver
1318 	tcp 	krb5gatekeeper 	krb5gatekeeper
1318 	udp 	krb5gatekeeper 	krb5gatekeeper
1319 	tcp 	amx-icsp 	AMX-ICSP
1319 	udp 	amx-icsp 	AMX-ICSP
1320 	tcp 	amx-axbnet 	AMX-AXBNET
1320 	udp 	amx-axbnet 	AMX-AXBNET
1321 	tcp 	pip 	PIP
1321 	udp 	pip 	PIP
1322 	tcp 	novation 	Novation
1322 	udp 	novation 	Novation
1323 	tcp 	brcd 	brcd
1323 	udp 	brcd 	brcd
1324 	tcp 	delta-mcp 	delta-mcp
1324 	udp 	delta-mcp 	delta-mcp
1325 	tcp 	dx-instrument 	DX-Instrument
1325 	udp 	dx-instrument 	DX-Instrument
1326 	tcp 	wimsic 	WIMSIC
1326 	udp 	wimsic 	WIMSIC
1327 	tcp 	ultrex 	Ultrex
1327 	udp 	ultrex 	Ultrex
1328 	tcp 	ewall 	EWALL
1328 	udp 	ewall 	EWALL
1329 	tcp 	netdb-export 	netdb-export
1329 	udp 	netdb-export 	netdb-export
1330 	tcp 	streetperfect 	StreetPerfect
1330 	udp 	streetperfect 	StreetPerfect
1331 	tcp 	intersan 	intersan
1331 	udp 	intersan 	intersan
1332 	tcp 	pcia-rxp-b 	PCIA RXP-B
1332 	udp 	pcia-rxp-b 	PCIA RXP-B
1333 	tcp 	passwrd-policy 	Password Policy
1333 	udp 	passwrd-policy 	Password Policy
1334 	tcp 	writesrv 	writesrv
1334 	udp 	writesrv 	writesrv
1335 	tcp 	digital-notary 	Digital Notary Protocol
1335 	udp 	digital-notary 	Digital Notary Protocol
1336 	tcp 	ischat 	Instant Service Chat
1336 	udp 	ischat 	Instant Service Chat
1337 	tcp 	menandmice-dns 	menandmice DNS
1337 	udp 	menandmice-dns 	menandmice DNS
1338 	tcp 	wmc-log-svc 	WMC-log-svr
1338 	udp 	wmc-log-svc 	WMC-log-svr
1339 	tcp 	kjtsiteserver 	kjtsiteserver
1339 	udp 	kjtsiteserver 	kjtsiteserver
1340 	tcp 	naap 	NAAP
1340 	udp 	naap 	NAAP
1341 	tcp 	qubes 	QuBES
1341 	udp 	qubes 	QuBES
1342 	tcp 	esbroker 	ESBroker
1342 	udp 	esbroker 	ESBroker
1343 	tcp 	re101 	re101
1343 	udp 	re101 	re101
1344 	tcp 	icap 	ICAP
1344 	udp 	icap 	ICAP
1345 	tcp 	vpjp 	VPJP
1345 	udp 	vpjp 	VPJP
1346 	tcp 	alta-ana-lm 	Alta Analytics License Manager
1346 	udp 	alta-ana-lm 	Alta Analytics License Manager
1347 	tcp 	bbn-mmc 	multi media conferencing
1347 	udp 	bbn-mmc 	multi media conferencing
1348 	tcp 	bbn-mmx 	multi media conferencing
1348 	udp 	bbn-mmx 	multi media conferencing
1349 	tcp 	sbook 	Registration Network Protocol
1349 	udp 	sbook 	Registration Network Protocol
1350 	tcp 	editbench 	Registration Network Protocol
1350 	udp 	editbench 	Registration Network Protocol
1351 	tcp 	equationbuilder 	Digital Tool Works (MIT)
1351 	udp 	equationbuilder 	Digital Tool Works (MIT)
1352 	tcp 	lotusnote 	Lotus Note
1352 	udp 	lotusnote 	Lotus Note
1353 	tcp 	relief 	Relief Consulting
1353 	udp 	relief 	Relief Consulting
1354 	tcp 	XSIP-network 	Five Across XSIP Network
1354 	udp 	XSIP-network 	Five Across XSIP Network
1355 	tcp 	intuitive-edge 	Intuitive Edge
1355 	udp 	intuitive-edge 	Intuitive Edge
1356 	tcp 	cuillamartin 	CuillaMartin Company
1356 	udp 	cuillamartin 	CuillaMartin Company
1357 	tcp 	pegboard 	Electronic PegBoard
1357 	udp 	pegboard 	Electronic PegBoard
1358 	tcp 	connlcli 	CONNLCLI
1358 	udp 	connlcli 	CONNLCLI
1359 	tcp 	ftsrv 	FTSRV
1359 	udp 	ftsrv 	FTSRV
1360 	tcp 	mimer 	MIMER
1360 	udp 	mimer 	MIMER
1361 	tcp 	linx 	LinX
1361 	udp 	linx 	LinX
1362 	tcp 	timeflies 	TimeFlies
1362 	udp 	timeflies 	TimeFlies
1363 	tcp 	ndm-requester 	Network DataMover Requester
1363 	udp 	ndm-requester 	Network DataMover Requester
1364 	tcp 	ndm-server 	Network DataMover Server
1364 	udp 	ndm-server 	Network DataMover Server
1365 	tcp 	adapt-sna 	Network Software Associates
1365 	udp 	adapt-sna 	Network Software Associates
1366 	tcp 	netware-csp 	Novell NetWare Comm Service Platform
1366 	udp 	netware-csp 	Novell NetWare Comm Service Platform
1367 	tcp 	dcs 	DCS
1367 	udp 	dcs 	DCS
1368 	tcp 	screencast 	ScreenCast
1368 	udp 	screencast 	ScreenCast
1369 	tcp 	gv-us 	GlobalView to Unix Shell
1369 	udp 	gv-us 	GlobalView to Unix Shell
1370 	tcp 	us-gv 	Unix Shell to GlobalView
1370 	udp 	us-gv 	Unix Shell to GlobalView
1371 	tcp 	fc-cli 	Fujitsu Config Protocol
1371 	udp 	fc-cli 	Fujitsu Config Protocol
1372 	tcp 	fc-ser 	Fujitsu Config Protocol
1372 	udp 	fc-ser 	Fujitsu Config Protocol
1373 	tcp 	chromagrafx 	Chromagrafx
1373 	udp 	chromagrafx 	Chromagrafx
1374 	tcp 	molly 	EPI Software Systems
1374 	udp 	molly 	EPI Software Systems
1375 	tcp 	bytex 	Bytex
1375 	udp 	bytex 	Bytex
1376 	tcp 	ibm-pps 	IBM Person to Person Software
1376 	udp 	ibm-pps 	IBM Person to Person Software
1377 	tcp 	cichlid 	Cichlid License Manager
1377 	udp 	cichlid 	Cichlid License Manager
1378 	tcp 	elan 	Elan License Manager
1378 	udp 	elan 	Elan License Manager
1379 	tcp 	dbreporter 	Integrity Solutions
1379 	udp 	dbreporter 	Integrity Solutions
1380 	tcp 	telesis-licman 	Telesis Network License Manager
1380 	udp 	telesis-licman 	Telesis Network License Manager
1381 	tcp 	apple-licman 	Apple Network License Manager
1381 	udp 	apple-licman 	Apple Network License Manager
1382 	tcp 	udt-os 	udt_os
IANA assigned this well-formed service name as a replacement for “udt_os”.
1382 	tcp 	udt_os 	udt_os
1382 	udp 	udt-os 	udt_os
IANA assigned this well-formed service name as a replacement for “udt_os”.
1382 	udp 	udt_os 	udt_os
1383 	tcp 	gwha 	GW Hannaway Network License Manager
1383 	udp 	gwha 	GW Hannaway Network License Manager
1384 	tcp 	os-licman 	Objective Solutions License Manager
1384 	udp 	os-licman 	Objective Solutions License Manager
1385 	tcp 	atex-elmd 	Atex Publishing License Manager
IANA assigned this well-formed service name as a replacement for “atex_elmd”.
1385 	tcp 	atex_elmd 	Atex Publishing License Manager
1385 	udp 	atex-elmd 	Atex Publishing License Manager
IANA assigned this well-formed service name as a replacement for “atex_elmd”.
1385 	udp 	atex_elmd 	Atex Publishing License Manager
1386 	tcp 	checksum 	CheckSum License Manager
1386 	udp 	checksum 	CheckSum License Manager
1387 	tcp 	cadsi-lm 	Computer Aided Design Software Inc LM
1387 	udp 	cadsi-lm 	Computer Aided Design Software Inc LM
1388 	tcp 	objective-dbc 	Objective Solutions DataBase Cache
1388 	udp 	objective-dbc 	Objective Solutions DataBase Cache
1389 	tcp 	iclpv-dm 	Document Manager
1389 	udp 	iclpv-dm 	Document Manager
1390 	tcp 	iclpv-sc 	Storage Controller
1390 	udp 	iclpv-sc 	Storage Controller
1391 	tcp 	iclpv-sas 	Storage Access Server
1391 	udp 	iclpv-sas 	Storage Access Server
1392 	tcp 	iclpv-pm 	Print Manager
1392 	udp 	iclpv-pm 	Print Manager
1393 	tcp 	iclpv-nls 	Network Log Server
1393 	udp 	iclpv-nls 	Network Log Server
1394 	tcp 	iclpv-nlc 	Network Log Client
1394 	udp 	iclpv-nlc 	Network Log Client
1395 	tcp 	iclpv-wsm 	PC Workstation Manager software
1395 	udp 	iclpv-wsm 	PC Workstation Manager software
1396 	tcp 	dvl-activemail 	DVL Active Mail
1396 	udp 	dvl-activemail 	DVL Active Mail
1397 	tcp 	audio-activmail 	Audio Active Mail
1397 	udp 	audio-activmail 	Audio Active Mail
1398 	tcp 	video-activmail 	Video Active Mail
1398 	udp 	video-activmail 	Video Active Mail
1399 	tcp 	cadkey-licman 	Cadkey License Manager
1399 	udp 	cadkey-licman 	Cadkey License Manager
1400 	tcp 	cadkey-tablet 	Cadkey Tablet Daemon
1400 	udp 	cadkey-tablet 	Cadkey Tablet Daemon
1401 	tcp 	goldleaf-licman 	Goldleaf License Manager
1401 	udp 	goldleaf-licman 	Goldleaf License Manager
1402 	tcp 	prm-sm-np 	Prospero Resource Manager
1402 	udp 	prm-sm-np 	Prospero Resource Manager
1403 	tcp 	prm-nm-np 	Prospero Resource Manager
1403 	udp 	prm-nm-np 	Prospero Resource Manager
1404 	tcp 	igi-lm 	Infinite Graphics License Manager
1404 	udp 	igi-lm 	Infinite Graphics License Manager
1405 	tcp 	ibm-res 	IBM Remote Execution Starter
1405 	udp 	ibm-res 	IBM Remote Execution Starter
1406 	tcp 	netlabs-lm 	NetLabs License Manager
1406 	udp 	netlabs-lm 	NetLabs License Manager
1407 	tcp 	tibet-server 	TIBET Data Server
1407 	udp 		Reserved
1408 	tcp 	sophia-lm 	Sophia License Manager
1408 	udp 	sophia-lm 	Sophia License Manager
1409 	tcp 	here-lm 	Here License Manager
1409 	udp 	here-lm 	Here License Manager
1410 	tcp 	hiq 	HiQ License Manager
1410 	udp 	hiq 	HiQ License Manager
1411 	tcp 	af 	AudioFile
1411 	udp 	af 	AudioFile
1412 	tcp 	innosys 	InnoSys
1412 	udp 	innosys 	InnoSys
1413 	tcp 	innosys-acl 	Innosys-ACL
1413 	udp 	innosys-acl 	Innosys-ACL
1414 	tcp 	ibm-mqseries 	IBM MQSeries
1414 	udp 	ibm-mqseries 	IBM MQSeries
1415 	tcp 	dbstar 	DBStar
1415 	udp 	dbstar 	DBStar
1416 	tcp 	novell-lu6-2 	Novell LU6.2
IANA assigned this well-formed service name as a replacement for “novell-lu6.2”.
1416 	tcp 	novell-lu6.2 	Novell LU6.2
1416 	udp 	novell-lu6-2 	Novell LU6.2
IANA assigned this well-formed service name as a replacement for “novell-lu6.2”.
1416 	udp 	novell-lu6.2 	Novell LU6.2
1417 	tcp 	timbuktu-srv1 	Timbuktu Service 1 Port
1417 	udp 	timbuktu-srv1 	Timbuktu Service 1 Port
1418 	tcp 	timbuktu-srv2 	Timbuktu Service 2 Port
1418 	udp 	timbuktu-srv2 	Timbuktu Service 2 Port
1419 	tcp 	timbuktu-srv3 	Timbuktu Service 3 Port
1419 	udp 	timbuktu-srv3 	Timbuktu Service 3 Port
1420 	tcp 	timbuktu-srv4 	Timbuktu Service 4 Port
1420 	udp 	timbuktu-srv4 	Timbuktu Service 4 Port
1421 	tcp 	gandalf-lm 	Gandalf License Manager
1421 	udp 	gandalf-lm 	Gandalf License Manager
1422 	tcp 	autodesk-lm 	Autodesk License Manager
1422 	udp 	autodesk-lm 	Autodesk License Manager
1423 	tcp 	essbase 	Essbase Arbor Software
1423 	udp 	essbase 	Essbase Arbor Software
1424 	tcp 	hybrid 	Hybrid Encryption Protocol
1424 	udp 	hybrid 	Hybrid Encryption Protocol
1425 	tcp 	zion-lm 	Zion Software License Manager
1425 	udp 	zion-lm 	Zion Software License Manager
1426 	tcp 	sais 	Satellite-data Acquisition System 1
1426 	udp 	sais 	Satellite-data Acquisition System 1
1427 	tcp 	mloadd 	mloadd monitoring tool
1427 	udp 	mloadd 	mloadd monitoring tool
1428 	tcp 	informatik-lm 	Informatik License Manager
1428 	udp 	informatik-lm 	Informatik License Manager
1429 	tcp 	nms 	Hypercom NMS
1429 	udp 	nms 	Hypercom NMS
1430 	tcp 	tpdu 	Hypercom TPDU
1430 	udp 	tpdu 	Hypercom TPDU
1431 	tcp 	rgtp 	Reverse Gossip Transport
1431 	udp 	rgtp 	Reverse Gossip Transport
1432 	tcp 	blueberry-lm 	Blueberry Software License Manager
1432 	udp 	blueberry-lm 	Blueberry Software License Manager
1433 	tcp 	ms-sql-s 	Microsoft-SQL-Server
1433 	udp 	ms-sql-s 	Microsoft-SQL-Server
1434 	tcp 	ms-sql-m 	Microsoft-SQL-Monitor
1434 	udp 	ms-sql-m 	Microsoft-SQL-Monitor
1435 	tcp 	ibm-cics 	IBM CICS
1435 	udp 	ibm-cics 	IBM CICS
1436 	tcp 	saism 	Satellite-data Acquisition System 2
1436 	udp 	saism 	Satellite-data Acquisition System 2
1437 	tcp 	tabula 	Tabula
1437 	udp 	tabula 	Tabula
1438 	tcp 	eicon-server 	Eicon Security Agent/Server
1438 	udp 	eicon-server 	Eicon Security Agent/Server
1439 	tcp 	eicon-x25 	Eicon X25/SNA Gateway
1439 	udp 	eicon-x25 	Eicon X25/SNA Gateway
1440 	tcp 	eicon-slp 	Eicon Service Location Protocol
1440 	udp 	eicon-slp 	Eicon Service Location Protocol
1441 	tcp 	cadis-1 	Cadis License Management
1441 	udp 	cadis-1 	Cadis License Management
1442 	tcp 	cadis-2 	Cadis License Management
1442 	udp 	cadis-2 	Cadis License Management
1443 	tcp 	ies-lm 	Integrated Engineering Software
1443 	udp 	ies-lm 	Integrated Engineering Software
1444 	tcp 	marcam-lm 	Marcam  License Management
1444 	udp 	marcam-lm 	Marcam  License Management
1445 	tcp 	proxima-lm 	Proxima License Manager
1445 	udp 	proxima-lm 	Proxima License Manager
1446 	tcp 	ora-lm 	Optical Research License Manager
1446 	udp 	ora-lm 	Optical Research License Manager
1447 	tcp 	apri-lm 	Applied Parallel Research LM
1447 	udp 	apri-lm 	Applied Parallel Research LM
1448 	tcp 	oc-lm 	OpenConnect License Manager
1448 	udp 	oc-lm 	OpenConnect License Manager
1449 	tcp 	peport 	PEport
1449 	udp 	peport 	PEport
1450 	tcp 	dwf 	Tandem Distributed Workbench Facility
1450 	udp 	dwf 	Tandem Distributed Workbench Facility
1451 	tcp 	infoman 	IBM Information Management
1451 	udp 	infoman 	IBM Information Management
1452 	tcp 	gtegsc-lm 	GTE Government Systems License Man
1452 	udp 	gtegsc-lm 	GTE Government Systems License Man
1453 	tcp 	genie-lm 	Genie License Manager
1453 	udp 	genie-lm 	Genie License Manager
1454 	tcp 	interhdl-elmd 	interHDL License Manager
IANA assigned this well-formed service name as a replacement for “interhdl_elmd”.
1454 	tcp 	interhdl_elmd 	interHDL License Manager
1454 	udp 	interhdl-elmd 	interHDL License Manager
IANA assigned this well-formed service name as a replacement for “interhdl_elmd”.
1454 	udp 	interhdl_elmd 	interHDL License Manager
1455 	tcp 	esl-lm 	ESL License Manager
1455 	udp 	esl-lm 	ESL License Manager
1456 	tcp 	dca 	DCA
1456 	udp 	dca 	DCA
1457 	tcp 	valisys-lm 	Valisys License Manager
1457 	udp 	valisys-lm 	Valisys License Manager
1458 	tcp 	nrcabq-lm 	Nichols Research Corp.
1458 	udp 	nrcabq-lm 	Nichols Research Corp.
1459 	tcp 	proshare1 	Proshare Notebook Application
1459 	udp 	proshare1 	Proshare Notebook Application
1460 	tcp 	proshare2 	Proshare Notebook Application
1460 	udp 	proshare2 	Proshare Notebook Application
1461 	tcp 	ibm-wrless-lan 	IBM Wireless LAN
IANA assigned this well-formed service name as a replacement for “ibm_wrless_lan”.
1461 	tcp 	ibm_wrless_lan 	IBM Wireless LAN
1461 	udp 	ibm-wrless-lan 	IBM Wireless LAN
IANA assigned this well-formed service name as a replacement for “ibm_wrless_lan”.
1461 	udp 	ibm_wrless_lan 	IBM Wireless LAN
1462 	tcp 	world-lm 	World License Manager
1462 	udp 	world-lm 	World License Manager
1463 	tcp 	nucleus 	Nucleus
1463 	udp 	nucleus 	Nucleus
1464 	tcp 	msl-lmd 	MSL License Manager
IANA assigned this well-formed service name as a replacement for “msl_lmd”.
1464 	tcp 	msl_lmd 	MSL License Manager
1464 	udp 	msl-lmd 	MSL License Manager
IANA assigned this well-formed service name as a replacement for “msl_lmd”.
1464 	udp 	msl_lmd 	MSL License Manager
1465 	tcp 	pipes 	Pipes Platform
1465 	udp 	pipes 	Pipes Platform
1466 	tcp 	oceansoft-lm 	Ocean Software License Manager
1466 	udp 	oceansoft-lm 	Ocean Software License Manager
1467 	tcp 	csdmbase 	CSDMBASE
1467 	udp 	csdmbase 	CSDMBASE
1468 	tcp 	csdm 	CSDM
1468 	udp 	csdm 	CSDM
1469 	tcp 	aal-lm 	Active Analysis Limited License Manager
1469 	udp 	aal-lm 	Active Analysis Limited License Manager
1470 	tcp 	uaiact 	Universal Analytics
1470 	udp 	uaiact 	Universal Analytics
1471 	tcp 	csdmbase 	csdmbase
1471 	udp 	csdmbase 	csdmbase
1472 	tcp 	csdm 	csdm
1472 	udp 	csdm 	csdm
1473 	tcp 	openmath 	OpenMath
1473 	udp 	openmath 	OpenMath
1474 	tcp 	telefinder 	Telefinder
1474 	udp 	telefinder 	Telefinder
1475 	tcp 	taligent-lm 	Taligent License Manager
1475 	udp 	taligent-lm 	Taligent License Manager
1476 	tcp 	clvm-cfg 	clvm-cfg
1476 	udp 	clvm-cfg 	clvm-cfg
1477 	tcp 	ms-sna-server 	ms-sna-server
1477 	udp 	ms-sna-server 	ms-sna-server
1478 	tcp 	ms-sna-base 	ms-sna-base
1478 	udp 	ms-sna-base 	ms-sna-base
1479 	tcp 	dberegister 	dberegister
1479 	udp 	dberegister 	dberegister
1480 	tcp 	pacerforum 	PacerForum
1480 	udp 	pacerforum 	PacerForum
1481 	tcp 	airs 	AIRS
1481 	udp 	airs 	AIRS
1482 	tcp 	miteksys-lm 	Miteksys License Manager
1482 	udp 	miteksys-lm 	Miteksys License Manager
1483 	tcp 	afs 	AFS License Manager
1483 	udp 	afs 	AFS License Manager
1484 	tcp 	confluent 	Confluent License Manager
1484 	udp 	confluent 	Confluent License Manager
1485 	tcp 	lansource 	LANSource
1485 	udp 	lansource 	LANSource
1486 	tcp 	nms-topo-serv 	nms_topo_serv
IANA assigned this well-formed service name as a replacement for “nms_topo_serv”.
1486 	tcp 	nms_topo_serv 	nms_topo_serv
1486 	udp 	nms-topo-serv 	nms_topo_serv
IANA assigned this well-formed service name as a replacement for “nms_topo_serv”.
1486 	udp 	nms_topo_serv 	nms_topo_serv
1487 	tcp 	localinfosrvr 	LocalInfoSrvr
1487 	udp 	localinfosrvr 	LocalInfoSrvr
1488 	tcp 	docstor 	DocStor
1488 	udp 	docstor 	DocStor
1489 	tcp 	dmdocbroker 	dmdocbroker
1489 	udp 	dmdocbroker 	dmdocbroker
1490 	tcp 	insitu-conf 	insitu-conf
1490 	udp 	insitu-conf 	insitu-conf
1491 			Unassigned
1492 	tcp 	stone-design-1 	stone-design-1
1492 	udp 	stone-design-1 	stone-design-1
1493 	tcp 	netmap-lm 	netmap_lm
IANA assigned this well-formed service name as a replacement for “netmap_lm”.
1493 	tcp 	netmap_lm 	netmap_lm
1493 	udp 	netmap-lm 	netmap_lm
IANA assigned this well-formed service name as a replacement for “netmap_lm”.
1493 	udp 	netmap_lm 	netmap_lm
1494 	tcp 	ica 	ica
1494 	udp 	ica 	ica
1495 	tcp 	cvc 	cvc
1495 	udp 	cvc 	cvc
1496 	tcp 	liberty-lm 	liberty-lm
1496 	udp 	liberty-lm 	liberty-lm
1497 	tcp 	rfx-lm 	rfx-lm
1497 	udp 	rfx-lm 	rfx-lm
1498 	tcp 	sybase-sqlany 	Sybase SQL Any
1498 	udp 	sybase-sqlany 	Sybase SQL Any
1499 	tcp 	fhc 	Federico Heinz Consultora
1499 	udp 	fhc 	Federico Heinz Consultora
1500 	tcp 	vlsi-lm 	VLSI License Manager
1500 	udp 	vlsi-lm 	VLSI License Manager
1501 	tcp 	saiscm 	Satellite-data Acquisition System 3
1501 	udp 	saiscm 	Satellite-data Acquisition System 3
1502 	tcp 	shivadiscovery 	Shiva
1502 	udp 	shivadiscovery 	Shiva
1503 	tcp 	imtc-mcs 	Databeam
1503 	udp 	imtc-mcs 	Databeam
1504 	tcp 	evb-elm 	EVB Software Engineering License Manager
1504 	udp 	evb-elm 	EVB Software Engineering License Manager
1505 	tcp 	funkproxy 	Funk Software, Inc.
1505 	udp 	funkproxy 	Funk Software, Inc.
1506 	tcp 	utcd 	Universal Time daemon (utcd)
1506 	udp 	utcd 	Universal Time daemon (utcd)
1507 	tcp 	symplex 	symplex
1507 	udp 	symplex 	symplex
1508 	tcp 	diagmond 	diagmond
1508 	udp 	diagmond 	diagmond
1509 	tcp 	robcad-lm 	Robcad, Ltd. License Manager
1509 	udp 	robcad-lm 	Robcad, Ltd. License Manager
1510 	tcp 	mvx-lm 	Midland Valley Exploration Ltd. Lic. Man.
1510 	udp 	mvx-lm 	Midland Valley Exploration Ltd. Lic. Man.
1511 	tcp 	3l-l1 	3l-l1
1511 	udp 	3l-l1 	3l-l1
1512 	tcp 	wins 	Microsoft’s Windows Internet Name Service
1512 	udp 	wins 	Microsoft’s Windows Internet Name Service
1513 	tcp 	fujitsu-dtc 	Fujitsu Systems Business of America, Inc
1513 	udp 	fujitsu-dtc 	Fujitsu Systems Business of America, Inc
1514 	tcp 	fujitsu-dtcns 	Fujitsu Systems Business of America, Inc
1514 	udp 	fujitsu-dtcns 	Fujitsu Systems Business of America, Inc
1515 	tcp 	ifor-protocol 	ifor-protocol
1515 	udp 	ifor-protocol 	ifor-protocol
1516 	tcp 	vpad 	Virtual Places Audio data
1516 	udp 	vpad 	Virtual Places Audio data
1517 	tcp 	vpac 	Virtual Places Audio control
1517 	udp 	vpac 	Virtual Places Audio control
1518 	tcp 	vpvd 	Virtual Places Video data
1518 	udp 	vpvd 	Virtual Places Video data
1519 	tcp 	vpvc 	Virtual Places Video control
1519 	udp 	vpvc 	Virtual Places Video control
1520 	tcp 	atm-zip-office 	atm zip office
1520 	udp 	atm-zip-office 	atm zip office
1521 	tcp 	ncube-lm 	nCube License Manager
1521 	udp 	ncube-lm 	nCube License Manager
1522 	tcp 	ricardo-lm 	Ricardo North America License Manager
1522 	udp 	ricardo-lm 	Ricardo North America License Manager
1523 	tcp 	cichild-lm 	cichild
1523 	udp 	cichild-lm 	cichild
1524 	tcp 	ingreslock 	ingres
1524 	udp 	ingreslock 	ingres
1525 	tcp 	orasrv 	oracle
1525 	udp 	orasrv 	oracle
1525 	tcp 	prospero-np 	Prospero Directory Service non-priv
1525 	udp 	prospero-np 	Prospero Directory Service non-priv
1526 	tcp 	pdap-np 	Prospero Data Access Prot non-priv
1526 	udp 	pdap-np 	Prospero Data Access Prot non-priv
1527 	tcp 	tlisrv 	oracle
1527 	udp 	tlisrv 	oracle
1528 	tcp 		Reserved
1528 	udp 	ngr-t 	NGR transport prot for mobile ad-hoc networks
1529 	tcp 	coauthor 	oracle
1529 	udp 	coauthor 	oracle
1530 	tcp 	rap-service 	rap-service
1530 	udp 	rap-service 	rap-service
1531 	tcp 	rap-listen 	rap-listen
1531 	udp 	rap-listen 	rap-listen
1532 	tcp 	miroconnect 	miroconnect
1532 	udp 	miroconnect 	miroconnect
1533 	tcp 	virtual-places 	Virtual Places Software
1533 	udp 	virtual-places 	Virtual Places Software
1534 	tcp 	micromuse-lm 	micromuse-lm
1534 	udp 	micromuse-lm 	micromuse-lm
1535 	tcp 	ampr-info 	ampr-info
1535 	udp 	ampr-info 	ampr-info
1536 	tcp 	ampr-inter 	ampr-inter
1536 	udp 	ampr-inter 	ampr-inter
1537 	tcp 	sdsc-lm 	isi-lm
1537 	udp 	sdsc-lm 	isi-lm
1538 	tcp 	3ds-lm 	3ds-lm
1538 	udp 	3ds-lm 	3ds-lm
1539 	tcp 	intellistor-lm 	Intellistor License Manager
1539 	udp 	intellistor-lm 	Intellistor License Manager
1540 	tcp 	rds 	rds
1540 	udp 	rds 	rds
1541 	tcp 	rds2 	rds2
1541 	udp 	rds2 	rds2
1542 	tcp 	gridgen-elmd 	gridgen-elmd
1542 	udp 	gridgen-elmd 	gridgen-elmd
1543 	tcp 	simba-cs 	simba-cs
1543 	udp 	simba-cs 	simba-cs
1544 	tcp 	aspeclmd 	aspeclmd
1544 	udp 	aspeclmd 	aspeclmd
1545 	tcp 	vistium-share 	vistium-share
1545 	udp 	vistium-share 	vistium-share
1546 	tcp 	abbaccuray 	abbaccuray
1546 	udp 	abbaccuray 	abbaccuray
1547 	tcp 	laplink 	laplink
1547 	udp 	laplink 	laplink
1548 	tcp 	axon-lm 	Axon License Manager
1548 	udp 	axon-lm 	Axon License Manager
1549 	tcp 	shivahose 	Shiva Hose
1549 	udp 	shivasound 	Shiva Sound
1550 	tcp 	3m-image-lm 	Image Storage license manager 3M Company
1550 	udp 	3m-image-lm 	Image Storage license manager 3M Company
1551 	tcp 	hecmtl-db 	HECMTL-DB
1551 	udp 	hecmtl-db 	HECMTL-DB
1552 	tcp 	pciarray 	pciarray
1552 	udp 	pciarray 	pciarray
1553 	tcp 	sna-cs 	sna-cs
1553 	udp 	sna-cs 	sna-cs
1554 	tcp 	caci-lm 	CACI Products Company License Manager
1554 	udp 	caci-lm 	CACI Products Company License Manager
1555 	tcp 	livelan 	livelan
1555 	udp 	livelan 	livelan
1556 	tcp 	veritas-pbx 	VERITAS Private Branch Exchange
IANA assigned this well-formed service name as a replacement for “veritas_pbx”.
1556 	tcp 	veritas_pbx 	VERITAS Private Branch Exchange
1556 	udp 	veritas-pbx 	VERITAS Private Branch Exchange
IANA assigned this well-formed service name as a replacement for “veritas_pbx”.
1556 	udp 	veritas_pbx 	VERITAS Private Branch Exchange
1557 	tcp 	arbortext-lm 	ArborText License Manager
1557 	udp 	arbortext-lm 	ArborText License Manager
1558 	tcp 	xingmpeg 	xingmpeg
1558 	udp 	xingmpeg 	xingmpeg
1559 	tcp 	web2host 	web2host
1559 	udp 	web2host 	web2host
1560 	tcp 	asci-val 	ASCI-RemoteSHADOW
1560 	udp 	asci-val 	ASCI-RemoteSHADOW
1561 	tcp 	facilityview 	facilityview
1561 	udp 	facilityview 	facilityview
1562 	tcp 	pconnectmgr 	pconnectmgr
1562 	udp 	pconnectmgr 	pconnectmgr
1563 	tcp 	cadabra-lm 	Cadabra License Manager
1563 	udp 	cadabra-lm 	Cadabra License Manager
1564 	tcp 	pay-per-view 	Pay-Per-View
1564 	udp 	pay-per-view 	Pay-Per-View
1565 	tcp 	winddlb 	WinDD
1565 	udp 	winddlb 	WinDD
1566 	tcp 	corelvideo 	CORELVIDEO
1566 	udp 	corelvideo 	CORELVIDEO
1567 	tcp 	jlicelmd 	jlicelmd
1567 	udp 	jlicelmd 	jlicelmd
1568 	tcp 	tsspmap 	tsspmap
1568 	udp 	tsspmap 	tsspmap
1569 	tcp 	ets 	ets
1569 	udp 	ets 	ets
1570 	tcp 	orbixd 	orbixd
1570 	udp 	orbixd 	orbixd
1571 	tcp 	rdb-dbs-disp 	Oracle Remote Data Base
1571 	udp 	rdb-dbs-disp 	Oracle Remote Data Base
1572 	tcp 	chip-lm 	Chipcom License Manager
1572 	udp 	chip-lm 	Chipcom License Manager
1573 	tcp 	itscomm-ns 	itscomm-ns
1573 	udp 	itscomm-ns 	itscomm-ns
1574 	tcp 	mvel-lm 	mvel-lm
1574 	udp 	mvel-lm 	mvel-lm
1575 	tcp 	oraclenames 	oraclenames
1575 	udp 	oraclenames 	oraclenames
1576 	tcp 	moldflow-lm 	Moldflow License Manager
1576 	udp 	moldflow-lm 	Moldflow License Manager
1577 	tcp 	hypercube-lm 	hypercube-lm
1577 	udp 	hypercube-lm 	hypercube-lm
1578 	tcp 	jacobus-lm 	Jacobus License Manager
1578 	udp 	jacobus-lm 	Jacobus License Manager
1579 	tcp 	ioc-sea-lm 	ioc-sea-lm
1579 	udp 	ioc-sea-lm 	ioc-sea-lm
1580 	tcp 	tn-tl-r1 	tn-tl-r1
1580 	udp 	tn-tl-r2 	tn-tl-r2
1581 	tcp 	mil-2045-47001 	MIL-2045-47001
1581 	udp 	mil-2045-47001 	MIL-2045-47001
1582 	tcp 	msims 	MSIMS
1582 	udp 	msims 	MSIMS
1583 	tcp 	simbaexpress 	simbaexpress
1583 	udp 	simbaexpress 	simbaexpress
1584 	tcp 	tn-tl-fd2 	tn-tl-fd2
1584 	udp 	tn-tl-fd2 	tn-tl-fd2
1585 	tcp 	intv 	intv
1585 	udp 	intv 	intv
1586 	tcp 	ibm-abtact 	ibm-abtact
1586 	udp 	ibm-abtact 	ibm-abtact
1587 	tcp 	pra-elmd 	pra_elmd
IANA assigned this well-formed service name as a replacement for “pra_elmd”.
1587 	tcp 	pra_elmd 	pra_elmd
1587 	udp 	pra-elmd 	pra_elmd
IANA assigned this well-formed service name as a replacement for “pra_elmd”.
1587 	udp 	pra_elmd 	pra_elmd
1588 	tcp 	triquest-lm 	triquest-lm
1588 	udp 	triquest-lm 	triquest-lm
1589 	tcp 	vqp 	VQP
1589 	udp 	vqp 	VQP
1590 	tcp 	gemini-lm 	gemini-lm
1590 	udp 	gemini-lm 	gemini-lm
1591 	tcp 	ncpm-pm 	ncpm-pm
1591 	udp 	ncpm-pm 	ncpm-pm
1592 	tcp 	commonspace 	commonspace
1592 	udp 	commonspace 	commonspace
1593 	tcp 	mainsoft-lm 	mainsoft-lm
1593 	udp 	mainsoft-lm 	mainsoft-lm
1594 	tcp 	sixtrak 	sixtrak
1594 	udp 	sixtrak 	sixtrak
1595 	tcp 	radio 	radio
1595 	udp 	radio 	radio
1596 	tcp 	radio-sm 	radio-sm
1596 	udp 	radio-bc 	radio-bc
1597 	tcp 	orbplus-iiop 	orbplus-iiop
1597 	udp 	orbplus-iiop 	orbplus-iiop
1598 	tcp 	picknfs 	picknfs
1598 	udp 	picknfs 	picknfs
1599 	tcp 	simbaservices 	simbaservices
1599 	udp 	simbaservices 	simbaservices
1600 	tcp 	issd 	issd
1600 	udp 	issd 	issd
1601 	tcp 	aas 	aas
1601 	udp 	aas 	aas
1602 	tcp 	inspect 	inspect
1602 	udp 	inspect 	inspect
1603 	tcp 	picodbc 	pickodbc
1603 	udp 	picodbc 	pickodbc
1604 	tcp 	icabrowser 	icabrowser
1604 	udp 	icabrowser 	icabrowser
1605 	tcp 	slp 	Salutation Manager (Salutation Protocol)
1605 	udp 	slp 	Salutation Manager (Salutation Protocol)
1606 	tcp 	slm-api 	Salutation Manager (SLM-API)
1606 	udp 	slm-api 	Salutation Manager (SLM-API)
1607 	tcp 	stt 	stt
1607 	udp 	stt 	stt
1608 	tcp 	smart-lm 	Smart Corp. License Manager
1608 	udp 	smart-lm 	Smart Corp. License Manager
1609 	tcp 	isysg-lm 	isysg-lm
1609 	udp 	isysg-lm 	isysg-lm
1610 	tcp 	taurus-wh 	taurus-wh
1610 	udp 	taurus-wh 	taurus-wh
1611 	tcp 	ill 	Inter Library Loan
1611 	udp 	ill 	Inter Library Loan
1612 	tcp 	netbill-trans 	NetBill Transaction Server
1612 	udp 	netbill-trans 	NetBill Transaction Server
1613 	tcp 	netbill-keyrep 	NetBill Key Repository
1613 	udp 	netbill-keyrep 	NetBill Key Repository
1614 	tcp 	netbill-cred 	NetBill Credential Server
1614 	udp 	netbill-cred 	NetBill Credential Server
1615 	tcp 	netbill-auth 	NetBill Authorization Server
1615 	udp 	netbill-auth 	NetBill Authorization Server
1616 	tcp 	netbill-prod 	NetBill Product Server
1616 	udp 	netbill-prod 	NetBill Product Server
1617 	tcp 	nimrod-agent 	Nimrod Inter-Agent Communication
1617 	udp 	nimrod-agent 	Nimrod Inter-Agent Communication
1618 	tcp 	skytelnet 	skytelnet
1618 	udp 	skytelnet 	skytelnet
1619 	tcp 	xs-openstorage 	xs-openstorage
1619 	udp 	xs-openstorage 	xs-openstorage
1620 	tcp 	faxportwinport 	faxportwinport
1620 	udp 	faxportwinport 	faxportwinport
1621 	tcp 	softdataphone 	softdataphone
1621 	udp 	softdataphone 	softdataphone
1622 	tcp 	ontime 	ontime
1622 	udp 	ontime 	ontime
1623 	tcp 	jaleosnd 	jaleosnd
1623 	udp 	jaleosnd 	jaleosnd
1624 	tcp 	udp-sr-port 	udp-sr-port
1624 	udp 	udp-sr-port 	udp-sr-port
1625 	tcp 	svs-omagent 	svs-omagent
1625 	udp 	svs-omagent 	svs-omagent
1626 	tcp 	shockwave 	Shockwave
1626 	udp 	shockwave 	Shockwave
1627 	tcp 	t128-gateway 	T.128 Gateway
1627 	udp 	t128-gateway 	T.128 Gateway
1628 	tcp 	lontalk-norm 	LonTalk normal
1628 	udp 	lontalk-norm 	LonTalk normal
1629 	tcp 	lontalk-urgnt 	LonTalk urgent
1629 	udp 	lontalk-urgnt 	LonTalk urgent
1630 	tcp 	oraclenet8cman 	Oracle Net8 Cman
1630 	udp 	oraclenet8cman 	Oracle Net8 Cman
1631 	tcp 	visitview 	Visit view
1631 	udp 	visitview 	Visit view
1632 	tcp 	pammratc 	PAMMRATC
1632 	udp 	pammratc 	PAMMRATC
1633 	tcp 	pammrpc 	PAMMRPC
1633 	udp 	pammrpc 	PAMMRPC
1634 	tcp 	loaprobe 	Log On America Probe
1634 	udp 	loaprobe 	Log On America Probe
1635 	tcp 	edb-server1 	EDB Server 1
1635 	udp 	edb-server1 	EDB Server 1
1636 	tcp 	isdc 	ISP shared public data control
1636 	udp 	isdc 	ISP shared public data control
1637 	tcp 	islc 	ISP shared local data control
1637 	udp 	islc 	ISP shared local data control
1638 	tcp 	ismc 	ISP shared management control
1638 	udp 	ismc 	ISP shared management control
1639 	tcp 	cert-initiator 	cert-initiator
1639 	udp 	cert-initiator 	cert-initiator
1640 	tcp 	cert-responder 	cert-responder
1640 	udp 	cert-responder 	cert-responder
1641 	tcp 	invision 	InVision
1641 	udp 	invision 	InVision
1642 	tcp 	isis-am 	isis-am
1642 	udp 	isis-am 	isis-am
1643 	tcp 	isis-ambc 	isis-ambc
1643 	udp 	isis-ambc 	isis-ambc
1644 	tcp 	saiseh 	Satellite-data Acquisition System 4
1644 	udp 	saiseh 	Satellite-data Acquisition System 4
1645 	tcp 	sightline 	SightLine
1645 	udp 	sightline 	SightLine
1646 	tcp 	sa-msg-port 	sa-msg-port
1646 	udp 	sa-msg-port 	sa-msg-port
1647 	tcp 	rsap 	rsap
1647 	udp 	rsap 	rsap
1648 	tcp 	concurrent-lm 	concurrent-lm
1648 	udp 	concurrent-lm 	concurrent-lm
1649 	tcp 	kermit 	kermit
1649 	udp 	kermit 	kermit
1650 	tcp 	nkd 	nkdn
1650 	udp 	nkd 	nkd
1651 	tcp 	shiva-confsrvr 	shiva_confsrvr
IANA assigned this well-formed service name as a replacement for “shiva_confsrvr”.
1651 	tcp 	shiva_confsrvr 	shiva_confsrvr
1651 	udp 	shiva-confsrvr 	shiva_confsrvr
IANA assigned this well-formed service name as a replacement for “shiva_confsrvr”.
1651 	udp 	shiva_confsrvr 	shiva_confsrvr
1652 	tcp 	xnmp 	xnmp
1652 	udp 	xnmp 	xnmp
1653 	tcp 	alphatech-lm 	alphatech-lm
1653 	udp 	alphatech-lm 	alphatech-lm
1654 	tcp 	stargatealerts 	stargatealerts
1654 	udp 	stargatealerts 	stargatealerts
1655 	tcp 	dec-mbadmin 	dec-mbadmin
1655 	udp 	dec-mbadmin 	dec-mbadmin
1656 	tcp 	dec-mbadmin-h 	dec-mbadmin-h
1656 	udp 	dec-mbadmin-h 	dec-mbadmin-h
1657 	tcp 	fujitsu-mmpdc 	fujitsu-mmpdc
1657 	udp 	fujitsu-mmpdc 	fujitsu-mmpdc
1658 	tcp 	sixnetudr 	sixnetudr
1658 	udp 	sixnetudr 	sixnetudr
1659 	tcp 	sg-lm 	Silicon Grail License Manager
1659 	udp 	sg-lm 	Silicon Grail License Manager
1660 	tcp 	skip-mc-gikreq 	skip-mc-gikreq
1660 	udp 	skip-mc-gikreq 	skip-mc-gikreq
1661 	tcp 	netview-aix-1 	netview-aix-1
1661 	udp 	netview-aix-1 	netview-aix-1
1662 	tcp 	netview-aix-2 	netview-aix-2
1662 	udp 	netview-aix-2 	netview-aix-2
1663 	tcp 	netview-aix-3 	netview-aix-3
1663 	udp 	netview-aix-3 	netview-aix-3
1664 	tcp 	netview-aix-4 	netview-aix-4
1664 	udp 	netview-aix-4 	netview-aix-4
1665 	tcp 	netview-aix-5 	netview-aix-5
1665 	udp 	netview-aix-5 	netview-aix-5
1666 	tcp 	netview-aix-6 	netview-aix-6
1666 	udp 	netview-aix-6 	netview-aix-6
1667 	tcp 	netview-aix-7 	netview-aix-7
1667 	udp 	netview-aix-7 	netview-aix-7
1668 	tcp 	netview-aix-8 	netview-aix-8
1668 	udp 	netview-aix-8 	netview-aix-8
1669 	tcp 	netview-aix-9 	netview-aix-9
1669 	udp 	netview-aix-9 	netview-aix-9
1670 	tcp 	netview-aix-10 	netview-aix-10
1670 	udp 	netview-aix-10 	netview-aix-10
1671 	tcp 	netview-aix-11 	netview-aix-11
1671 	udp 	netview-aix-11 	netview-aix-11
1672 	tcp 	netview-aix-12 	netview-aix-12
1672 	udp 	netview-aix-12 	netview-aix-12
1673 	tcp 	proshare-mc-1 	Intel Proshare Multicast
1673 	udp 	proshare-mc-1 	Intel Proshare Multicast
1674 	tcp 	proshare-mc-2 	Intel Proshare Multicast
1674 	udp 	proshare-mc-2 	Intel Proshare Multicast
1675 	tcp 	pdp 	Pacific Data Products
1675 	udp 	pdp 	Pacific Data Products
1676 	tcp 	netcomm1 	netcomm1
1676 	udp 	netcomm2 	netcomm2
1677 	tcp 	groupwise 	groupwise
1677 	udp 	groupwise 	groupwise
1678 	tcp 	prolink 	prolink
1678 	udp 	prolink 	prolink
1679 	tcp 	darcorp-lm 	darcorp-lm
1679 	udp 	darcorp-lm 	darcorp-lm
1680 	tcp 	microcom-sbp 	microcom-sbp
1680 	udp 	microcom-sbp 	microcom-sbp
1681 	tcp 	sd-elmd 	sd-elmd
1681 	udp 	sd-elmd 	sd-elmd
1682 	tcp 	lanyon-lantern 	lanyon-lantern
1682 	udp 	lanyon-lantern 	lanyon-lantern
1683 	tcp 	ncpm-hip 	ncpm-hip
1683 	udp 	ncpm-hip 	ncpm-hip
1684 	tcp 	snaresecure 	SnareSecure
1684 	udp 	snaresecure 	SnareSecure
1685 	tcp 	n2nremote 	n2nremote
1685 	udp 	n2nremote 	n2nremote
1686 	tcp 	cvmon 	cvmon
1686 	udp 	cvmon 	cvmon
1687 	tcp 	nsjtp-ctrl 	nsjtp-ctrl
1687 	udp 	nsjtp-ctrl 	nsjtp-ctrl
1688 	tcp 	nsjtp-data 	nsjtp-data
1688 	udp 	nsjtp-data 	nsjtp-data
1689 	tcp 	firefox 	firefox
1689 	udp 	firefox 	firefox
1690 	tcp 	ng-umds 	ng-umds
1690 	udp 	ng-umds 	ng-umds
1691 	tcp 	empire-empuma 	empire-empuma
1691 	udp 	empire-empuma 	empire-empuma
1692 	tcp 	sstsys-lm 	sstsys-lm
1692 	udp 	sstsys-lm 	sstsys-lm
1693 	tcp 	rrirtr 	rrirtr
1693 	udp 	rrirtr 	rrirtr
1694 	tcp 	rrimwm 	rrimwm
1694 	udp 	rrimwm 	rrimwm
1695 	tcp 	rrilwm 	rrilwm
1695 	udp 	rrilwm 	rrilwm
1696 	tcp 	rrifmm 	rrifmm
1696 	udp 	rrifmm 	rrifmm
1697 	tcp 	rrisat 	rrisat
1697 	udp 	rrisat 	rrisat
1698 	tcp 	rsvp-encap-1 	RSVP-ENCAPSULATION-1
1698 	udp 	rsvp-encap-1 	RSVP-ENCAPSULATION-1
1699 	tcp 	rsvp-encap-2 	RSVP-ENCAPSULATION-2
1699 	udp 	rsvp-encap-2 	RSVP-ENCAPSULATION-2
1700 	tcp 	mps-raft 	mps-raft
1700 	udp 	mps-raft 	mps-raft
1701 	tcp 	l2f 	l2f
1701 	udp 	l2f 	l2f
1701 	tcp 	l2tp 	l2tp
1701 	udp 	l2tp 	l2tp
1702 	tcp 	deskshare 	deskshare
1702 	udp 	deskshare 	deskshare
1703 	tcp 	hb-engine 	hb-engine
1703 	udp 	hb-engine 	hb-engine
1704 	tcp 	bcs-broker 	bcs-broker
1704 	udp 	bcs-broker 	bcs-broker
1705 	tcp 	slingshot 	slingshot
1705 	udp 	slingshot 	slingshot
1706 	tcp 	jetform 	jetform
1706 	udp 	jetform 	jetform
1707 	tcp 	vdmplay 	vdmplay
1707 	udp 	vdmplay 	vdmplay
1708 	tcp 	gat-lmd 	gat-lmd
1708 	udp 	gat-lmd 	gat-lmd
1709 	tcp 	centra 	centra
1709 	udp 	centra 	centra
1710 	tcp 	impera 	impera
1710 	udp 	impera 	impera
1711 	tcp 	pptconference 	pptconference
1711 	udp 	pptconference 	pptconference
1712 	tcp 	registrar 	resource monitoring service
1712 	udp 	registrar 	resource monitoring service
1713 	tcp 	conferencetalk 	ConferenceTalk
1713 	udp 	conferencetalk 	ConferenceTalk
1714 	tcp 	sesi-lm 	sesi-lm
1714 	udp 	sesi-lm 	sesi-lm
1715 	tcp 	houdini-lm 	houdini-lm
1715 	udp 	houdini-lm 	houdini-lm
1716 	tcp 	xmsg 	xmsg
1716 	udp 	xmsg 	xmsg
1717 	tcp 	fj-hdnet 	fj-hdnet
1717 	udp 	fj-hdnet 	fj-hdnet
1718 	tcp 	h323gatedisc 	H.323 Multicast Gatekeeper Discover
1718 	udp 	h323gatedisc 	H.323 Multicast Gatekeeper Discover
1719 	tcp 	h323gatestat 	H.323 Unicast Gatekeeper Signaling
1719 	udp 	h323gatestat 	H.323 Unicast Gatekeeper Signaling
1720 	tcp 	h323hostcall 	H.323 Call Control Signalling
1720 	udp 	h323hostcall 	H.323 Call Control Signalling
1720 	sctp 	h323hostcall 	H.323 Call Control
1721 	tcp 	caicci 	caicci
1721 	udp 	caicci 	caicci
1722 	tcp 	hks-lm 	HKS License Manager
1722 	udp 	hks-lm 	HKS License Manager
1723 	tcp 	pptp 	pptp
1723 	udp 	pptp 	pptp
1724 	tcp 	csbphonemaster 	csbphonemaster
1724 	udp 	csbphonemaster 	csbphonemaster
1725 	tcp 	iden-ralp 	iden-ralp
1725 	udp 	iden-ralp 	iden-ralp
1726 	tcp 	iberiagames 	IBERIAGAMES
1726 	udp 	iberiagames 	IBERIAGAMES
1727 	tcp 	winddx 	winddx
1727 	udp 	winddx 	winddx
1728 	tcp 	telindus 	TELINDUS
1728 	udp 	telindus 	TELINDUS
1729 	tcp 	citynl 	CityNL License Management
1729 	udp 	citynl 	CityNL License Management
1730 	tcp 	roketz 	roketz
1730 	udp 	roketz 	roketz
1731 	tcp 	msiccp 	MSICCP
1731 	udp 	msiccp 	MSICCP
1732 	tcp 	proxim 	proxim
1732 	udp 	proxim 	proxim
1733 	tcp 	siipat 	SIMS – SIIPAT Protocol for Alarm Transmission
1733 	udp 	siipat 	SIMS – SIIPAT Protocol for Alarm Transmission
1734 	tcp 	cambertx-lm 	Camber Corporation License Management
1734 	udp 	cambertx-lm 	Camber Corporation License Management
1735 	tcp 	privatechat 	PrivateChat
1735 	udp 	privatechat 	PrivateChat
1736 	tcp 	street-stream 	street-stream
1736 	udp 	street-stream 	street-stream
1737 	tcp 	ultimad 	ultimad
1737 	udp 	ultimad 	ultimad
1738 	tcp 	gamegen1 	GameGen1
1738 	udp 	gamegen1 	GameGen1
1739 	tcp 	webaccess 	webaccess
1739 	udp 	webaccess 	webaccess
1740 	tcp 	encore 	encore
1740 	udp 	encore 	encore
1741 	tcp 	cisco-net-mgmt 	cisco-net-mgmt
1741 	udp 	cisco-net-mgmt 	cisco-net-mgmt
1742 	tcp 	3Com-nsd 	3Com-nsd
1742 	udp 	3Com-nsd 	3Com-nsd
1743 	tcp 	cinegrfx-lm 	Cinema Graphics License Manager
1743 	udp 	cinegrfx-lm 	Cinema Graphics License Manager
1744 	tcp 	ncpm-ft 	ncpm-ft
1744 	udp 	ncpm-ft 	ncpm-ft
1745 	tcp 	remote-winsock 	remote-winsock
1745 	udp 	remote-winsock 	remote-winsock
1746 	tcp 	ftrapid-1 	ftrapid-1
1746 	udp 	ftrapid-1 	ftrapid-1
1747 	tcp 	ftrapid-2 	ftrapid-2
1747 	udp 	ftrapid-2 	ftrapid-2
1748 	tcp 	oracle-em1 	oracle-em1
1748 	udp 	oracle-em1 	oracle-em1
1749 	tcp 	aspen-services 	aspen-services
1749 	udp 	aspen-services 	aspen-services
1750 	tcp 	sslp 	Simple Socket Library’s PortMaster
1750 	udp 	sslp 	Simple Socket Library’s PortMaster
1751 	tcp 	swiftnet 	SwiftNet
1751 	udp 	swiftnet 	SwiftNet
1752 	tcp 	lofr-lm 	Leap of Faith Research License Manager
1752 	udp 	lofr-lm 	Leap of Faith Research License Manager
1753 	tcp 	predatar-comms 	Predatar Comms Service
1753 	udp 		Reserved
1754 	tcp 	oracle-em2 	oracle-em2
1754 	udp 	oracle-em2 	oracle-em2
1755 	tcp 	ms-streaming 	ms-streaming
1755 	udp 	ms-streaming 	ms-streaming
1756 	tcp 	capfast-lmd 	capfast-lmd
1756 	udp 	capfast-lmd 	capfast-lmd
1757 	tcp 	cnhrp 	cnhrp
1757 	udp 	cnhrp 	cnhrp
1758 	tcp 	tftp-mcast 	tftp-mcast
1758 	udp 	tftp-mcast 	tftp-mcast
1759 	tcp 	spss-lm 	SPSS License Manager
1759 	udp 	spss-lm 	SPSS License Manager
1760 	tcp 	www-ldap-gw 	www-ldap-gw
1760 	udp 	www-ldap-gw 	www-ldap-gw
1761 	tcp 	cft-0 	cft-0
1761 	udp 	cft-0 	cft-0
1762 	tcp 	cft-1 	cft-1
1762 	udp 	cft-1 	cft-1
1763 	tcp 	cft-2 	cft-2
1763 	udp 	cft-2 	cft-2
1764 	tcp 	cft-3 	cft-3
1764 	udp 	cft-3 	cft-3
1765 	tcp 	cft-4 	cft-4
1765 	udp 	cft-4 	cft-4
1766 	tcp 	cft-5 	cft-5
1766 	udp 	cft-5 	cft-5
1767 	tcp 	cft-6 	cft-6
1767 	udp 	cft-6 	cft-6
1768 	tcp 	cft-7 	cft-7
1768 	udp 	cft-7 	cft-7
1769 	tcp 	bmc-net-adm 	bmc-net-adm
1769 	udp 	bmc-net-adm 	bmc-net-adm
1770 	tcp 	bmc-net-svc 	bmc-net-svc
1770 	udp 	bmc-net-svc 	bmc-net-svc
1771 	tcp 	vaultbase 	vaultbase
1771 	udp 	vaultbase 	vaultbase
1772 	tcp 	essweb-gw 	EssWeb Gateway
1772 	udp 	essweb-gw 	EssWeb Gateway
1773 	tcp 	kmscontrol 	KMSControl
1773 	udp 	kmscontrol 	KMSControl
1774 	tcp 	global-dtserv 	global-dtserv
1774 	udp 	global-dtserv 	global-dtserv
1775 	tcp 	vdab 	data int. between visual processing containers
1775 	udp 		Reserved
1776 	tcp 	femis 	Federal Emergency Management Info System
1776 	udp 	femis 	Federal Emergency Management Info System
1777 	tcp 	powerguardian 	powerguardian
1777 	udp 	powerguardian 	powerguardian
1778 	tcp 	prodigy-intrnet 	prodigy-internet
1778 	udp 	prodigy-intrnet 	prodigy-internet
1779 	tcp 	pharmasoft 	pharmasoft
1779 	udp 	pharmasoft 	pharmasoft
1780 	tcp 	dpkeyserv 	dpkeyserv
1780 	udp 	dpkeyserv 	dpkeyserv
1781 	tcp 	answersoft-lm 	answersoft-lm
1781 	udp 	answersoft-lm 	answersoft-lm
1782 	tcp 	hp-hcip 	hp-hcip
1782 	udp 	hp-hcip 	hp-hcip
1783 			Decomissioned Port 04/14/00, ms
1784 	tcp 	finle-lm 	Finle License Manager
1784 	udp 	finle-lm 	Finle License Manager
1785 	tcp 	windlm 	Wind River Systems License Manager
1785 	udp 	windlm 	Wind River Systems License Manager
1786 	tcp 	funk-logger 	funk-logger
1786 	udp 	funk-logger 	funk-logger
1787 	tcp 	funk-license 	funk-license
1787 	udp 	funk-license 	funk-license
1788 	tcp 	psmond 	psmond
1788 	udp 	psmond 	psmond
1789 	tcp 	hello 	hello
1789 	udp 	hello 	hello
1790 	tcp 	nmsp 	Narrative Media Streaming Protocol
1790 	udp 	nmsp 	Narrative Media Streaming Protocol
1791 	tcp 	ea1 	EA1
1791 	udp 	ea1 	EA1
1792 	tcp 	ibm-dt-2 	ibm-dt-2
1792 	udp 	ibm-dt-2 	ibm-dt-2
1793 	tcp 	rsc-robot 	rsc-robot
1793 	udp 	rsc-robot 	rsc-robot
1794 	tcp 	cera-bcm 	cera-bcm
1794 	udp 	cera-bcm 	cera-bcm
1795 	tcp 	dpi-proxy 	dpi-proxy
1795 	udp 	dpi-proxy 	dpi-proxy
1796 	tcp 	vocaltec-admin 	Vocaltec Server Administration
1796 	udp 	vocaltec-admin 	Vocaltec Server Administration
1797 	tcp 	uma 	UMA
1797 	udp 	uma 	UMA
1798 	tcp 	etp 	Event Transfer Protocol
1798 	udp 	etp 	Event Transfer Protocol
1799 	tcp 	netrisk 	NETRISK
1799 	udp 	netrisk 	NETRISK
1800 	tcp 	ansys-lm 	ANSYS-License manager
1800 	udp 	ansys-lm 	ANSYS-License manager
1801 	tcp 	msmq 	Microsoft Message Que
1801 	udp 	msmq 	Microsoft Message Que
1802 	tcp 	concomp1 	ConComp1
1802 	udp 	concomp1 	ConComp1
1803 	tcp 	hp-hcip-gwy 	HP-HCIP-GWY
1803 	udp 	hp-hcip-gwy 	HP-HCIP-GWY
1804 	tcp 	enl 	ENL
1804 	udp 	enl 	ENL
1805 	tcp 	enl-name 	ENL-Name
1805 	udp 	enl-name 	ENL-Name
1806 	tcp 	musiconline 	Musiconline
1806 	udp 	musiconline 	Musiconline
1807 	tcp 	fhsp 	Fujitsu Hot Standby Protocol
1807 	udp 	fhsp 	Fujitsu Hot Standby Protocol
1808 	tcp 	oracle-vp2 	Oracle-VP2
1808 	udp 	oracle-vp2 	Oracle-VP2
1809 	tcp 	oracle-vp1 	Oracle-VP1
1809 	udp 	oracle-vp1 	Oracle-VP1
1810 	tcp 	jerand-lm 	Jerand License Manager
1810 	udp 	jerand-lm 	Jerand License Manager
1811 	tcp 	scientia-sdb 	Scientia-SDB
1811 	udp 	scientia-sdb 	Scientia-SDB
1812 	tcp 	radius 	RADIUS
1812 	udp 	radius 	RADIUS
1813 	tcp 	radius-acct 	RADIUS Accounting
1813 	udp 	radius-acct 	RADIUS Accounting
1814 	tcp 	tdp-suite 	TDP Suite
1814 	udp 	tdp-suite 	TDP Suite
1815 	tcp 	mmpft 	MMPFT
1815 	udp 	mmpft 	MMPFT
1816 	tcp 	harp 	HARP
1816 	udp 	harp 	HARP
1817 	tcp 	rkb-oscs 	RKB-OSCS
1817 	udp 	rkb-oscs 	RKB-OSCS
1818 	tcp 	etftp 	Enhanced Trivial File Transfer Protocol
1818 	udp 	etftp 	Enhanced Trivial File Transfer Protocol
1819 	tcp 	plato-lm 	Plato License Manager
1819 	udp 	plato-lm 	Plato License Manager
1820 	tcp 	mcagent 	mcagent
1820 	udp 	mcagent 	mcagent
1821 	tcp 	donnyworld 	donnyworld
1821 	udp 	donnyworld 	donnyworld
1822 	tcp 	es-elmd 	es-elmd
1822 	udp 	es-elmd 	es-elmd
1823 	tcp 	unisys-lm 	Unisys Natural Language License Manager
1823 	udp 	unisys-lm 	Unisys Natural Language License Manager
1824 	tcp 	metrics-pas 	metrics-pas
1824 	udp 	metrics-pas 	metrics-pas
1825 	tcp 	direcpc-video 	DirecPC Video
1825 	udp 	direcpc-video 	DirecPC Video
1826 	tcp 	ardt 	ARDT
1826 	udp 	ardt 	ARDT
1827 	tcp 	asi 	ASI
1827 	udp 	asi 	ASI
1828 	tcp 	itm-mcell-u 	itm-mcell-u
1828 	udp 	itm-mcell-u 	itm-mcell-u
1829 	tcp 	optika-emedia 	Optika eMedia
1829 	udp 	optika-emedia 	Optika eMedia
1830 	tcp 	net8-cman 	Oracle Net8 CMan Admin
1830 	udp 	net8-cman 	Oracle Net8 CMan Admin
1831 	tcp 	myrtle 	Myrtle
1831 	udp 	myrtle 	Myrtle
1832 	tcp 	tht-treasure 	ThoughtTreasure
1832 	udp 	tht-treasure 	ThoughtTreasure
1833 	tcp 	udpradio 	udpradio
1833 	udp 	udpradio 	udpradio
1834 	tcp 	ardusuni 	ARDUS Unicast
1834 	udp 	ardusuni 	ARDUS Unicast
1835 	tcp 	ardusmul 	ARDUS Multicast
1835 	udp 	ardusmul 	ARDUS Multicast
1836 	tcp 	ste-smsc 	ste-smsc
1836 	udp 	ste-smsc 	ste-smsc
1837 	tcp 	csoft1 	csoft1
1837 	udp 	csoft1 	csoft1
1838 	tcp 	talnet 	TALNET
1838 	udp 	talnet 	TALNET
1839 	tcp 	netopia-vo1 	netopia-vo1
1839 	udp 	netopia-vo1 	netopia-vo1
1840 	tcp 	netopia-vo2 	netopia-vo2
1840 	udp 	netopia-vo2 	netopia-vo2
1841 	tcp 	netopia-vo3 	netopia-vo3
1841 	udp 	netopia-vo3 	netopia-vo3
1842 	tcp 	netopia-vo4 	netopia-vo4
1842 	udp 	netopia-vo4 	netopia-vo4
1843 	tcp 	netopia-vo5 	netopia-vo5
1843 	udp 	netopia-vo5 	netopia-vo5
1844 	tcp 	direcpc-dll 	DirecPC-DLL
1844 	udp 	direcpc-dll 	DirecPC-DLL
1845 	tcp 	altalink 	altalink
1845 	udp 	altalink 	altalink
1846 	tcp 	tunstall-pnc 	Tunstall PNC
1846 	udp 	tunstall-pnc 	Tunstall PNC
1847 	tcp 	slp-notify 	SLP Notification
1847 	udp 	slp-notify 	SLP Notification
1848 	tcp 	fjdocdist 	fjdocdist
1848 	udp 	fjdocdist 	fjdocdist
1849 	tcp 	alpha-sms 	ALPHA-SMS
1849 	udp 	alpha-sms 	ALPHA-SMS
1850 	tcp 	gsi 	GSI
1850 	udp 	gsi 	GSI
1851 	tcp 	ctcd 	ctcd
1851 	udp 	ctcd 	ctcd
1852 	tcp 	virtual-time 	Virtual Time
1852 	udp 	virtual-time 	Virtual Time
1853 	tcp 	vids-avtp 	VIDS-AVTP
1853 	udp 	vids-avtp 	VIDS-AVTP
1854 	tcp 	buddy-draw 	Buddy Draw
1854 	udp 	buddy-draw 	Buddy Draw
1855 	tcp 	fiorano-rtrsvc 	Fiorano RtrSvc
1855 	udp 	fiorano-rtrsvc 	Fiorano RtrSvc
1856 	tcp 	fiorano-msgsvc 	Fiorano MsgSvc
1856 	udp 	fiorano-msgsvc 	Fiorano MsgSvc
1857 	tcp 	datacaptor 	DataCaptor
1857 	udp 	datacaptor 	DataCaptor
1858 	tcp 	privateark 	PrivateArk
1858 	udp 	privateark 	PrivateArk
1859 	tcp 	gammafetchsvr 	Gamma Fetcher Server
1859 	udp 	gammafetchsvr 	Gamma Fetcher Server
1860 	tcp 	sunscalar-svc 	SunSCALAR Services
1860 	udp 	sunscalar-svc 	SunSCALAR Services
1861 	tcp 	lecroy-vicp 	LeCroy VICP
1861 	udp 	lecroy-vicp 	LeCroy VICP
1862 	tcp 	mysql-cm-agent 	MySQL Cluster Manager Agent
1862 	udp 	mysql-cm-agent 	MySQL Cluster Manager Agent
1863 	tcp 	msnp 	MSNP
1863 	udp 	msnp 	MSNP
1864 	tcp 	paradym-31port 	Paradym 31 Port
1864 	udp 	paradym-31port 	Paradym 31 Port
1865 	tcp 	entp 	ENTP
1865 	udp 	entp 	ENTP
1866 	tcp 	swrmi 	swrmi
1866 	udp 	swrmi 	swrmi
1867 	tcp 	udrive 	UDRIVE
1867 	udp 	udrive 	UDRIVE
1868 	tcp 	viziblebrowser 	VizibleBrowser
1868 	udp 	viziblebrowser 	VizibleBrowser
1869 	tcp 	transact 	TransAct
1869 	udp 	transact 	TransAct
1870 	tcp 	sunscalar-dns 	SunSCALAR DNS Service
1870 	udp 	sunscalar-dns 	SunSCALAR DNS Service
1871 	tcp 	canocentral0 	Cano Central 0
1871 	udp 	canocentral0 	Cano Central 0
1872 	tcp 	canocentral1 	Cano Central 1
1872 	udp 	canocentral1 	Cano Central 1
1873 	tcp 	fjmpjps 	Fjmpjps
1873 	udp 	fjmpjps 	Fjmpjps
1874 	tcp 	fjswapsnp 	Fjswapsnp
1874 	udp 	fjswapsnp 	Fjswapsnp
1875 	tcp 	westell-stats 	westell stats
1875 	udp 	westell-stats 	westell stats
1876 	tcp 	ewcappsrv 	ewcappsrv
1876 	udp 	ewcappsrv 	ewcappsrv
1877 	tcp 	hp-webqosdb 	hp-webqosdb
1877 	udp 	hp-webqosdb 	hp-webqosdb
1878 	tcp 	drmsmc 	drmsmc
1878 	udp 	drmsmc 	drmsmc
1879 	tcp 	nettgain-nms 	NettGain NMS
1879 	udp 	nettgain-nms 	NettGain NMS
1880 	tcp 	vsat-control 	Gilat VSAT Control
1880 	udp 	vsat-control 	Gilat VSAT Control
1881 	tcp 	ibm-mqseries2 	IBM WebSphere MQ Everyplace
1881 	udp 	ibm-mqseries2 	IBM WebSphere MQ Everyplace
1882 	tcp 	ecsqdmn 	CA eTrust Common Services
1882 	udp 	ecsqdmn 	CA eTrust Common Services
1883 	tcp 	mqtt 	Message Queuing Telemetry Transport Protocol
1883 	udp 	mqtt 	Message Queuing Telemetry Transport Protocol
1884 	tcp 	idmaps 	Internet Distance Map Svc
1884 	udp 	idmaps 	Internet Distance Map Svc
1885 	tcp 	vrtstrapserver 	Veritas Trap Server
1885 	udp 	vrtstrapserver 	Veritas Trap Server
1886 	tcp 	leoip 	Leonardo over IP
1886 	udp 	leoip 	Leonardo over IP
1887 	tcp 	filex-lport 	FileX Listening Port
1887 	udp 	filex-lport 	FileX Listening Port
1888 	tcp 	ncconfig 	NC Config Port
1888 	udp 	ncconfig 	NC Config Port
1889 	tcp 	unify-adapter 	Unify Web Adapter Service
1889 	udp 	unify-adapter 	Unify Web Adapter Service
1890 	tcp 	wilkenlistener 	wilkenListener
1890 	udp 	wilkenlistener 	wilkenListener
1891 	tcp 	childkey-notif 	ChildKey Notification
1891 	udp 	childkey-notif 	ChildKey Notification
1892 	tcp 	childkey-ctrl 	ChildKey Control
1892 	udp 	childkey-ctrl 	ChildKey Control
1893 	tcp 	elad 	ELAD Protocol
1893 	udp 	elad 	ELAD Protocol
1894 	tcp 	o2server-port 	O2Server Port
1894 	udp 	o2server-port 	O2Server Port
1895 	tcp 		unassigned
1895 	udp 		unassigned
1896 	tcp 	b-novative-ls 	b-novative license server
1896 	udp 	b-novative-ls 	b-novative license server
1897 	tcp 	metaagent 	MetaAgent
1897 	udp 	metaagent 	MetaAgent
1898 	tcp 	cymtec-port 	Cymtec secure management
1898 	udp 	cymtec-port 	Cymtec secure management
1899 	tcp 	mc2studios 	MC2Studios
1899 	udp 	mc2studios 	MC2Studios
1900 	tcp 	ssdp 	SSDP
1900 	udp 	ssdp 	SSDP
1901 	tcp 	fjicl-tep-a 	Fujitsu ICL Terminal Emulator Program A
1901 	udp 	fjicl-tep-a 	Fujitsu ICL Terminal Emulator Program A
1902 	tcp 	fjicl-tep-b 	Fujitsu ICL Terminal Emulator Program B
1902 	udp 	fjicl-tep-b 	Fujitsu ICL Terminal Emulator Program B
1903 	tcp 	linkname 	Local Link Name Resolution
1903 	udp 	linkname 	Local Link Name Resolution
1904 	tcp 	fjicl-tep-c 	Fujitsu ICL Terminal Emulator Program C
1904 	udp 	fjicl-tep-c 	Fujitsu ICL Terminal Emulator Program C
1905 	tcp 	sugp 	Secure UP.Link Gateway Protocol
1905 	udp 	sugp 	Secure UP.Link Gateway Protocol
1906 	tcp 	tpmd 	TPortMapperReq
1906 	udp 	tpmd 	TPortMapperReq
1907 	tcp 	intrastar 	IntraSTAR
1907 	udp 	intrastar 	IntraSTAR
1908 	tcp 	dawn 	Dawn
1908 	udp 	dawn 	Dawn
1909 	tcp 	global-wlink 	Global World Link
1909 	udp 	global-wlink 	Global World Link
1910 	tcp 	ultrabac 	UltraBac Software communications port
1910 	udp 	ultrabac 	UltraBac Software communications port
1911 	tcp 	mtp 	Starlight Networks Multimedia Transport Prot
1911 	udp 	mtp 	Starlight Networks Multimedia Transport Prot
1912 	tcp 	rhp-iibp 	rhp-iibp
1912 	udp 	rhp-iibp 	rhp-iibp
1913 	tcp 	armadp 	armadp
1913 	udp 	armadp 	armadp
1914 	tcp 	elm-momentum 	Elm-Momentum
1914 	udp 	elm-momentum 	Elm-Momentum
1915 	tcp 	facelink 	FACELINK
1915 	udp 	facelink 	FACELINK
1916 	tcp 	persona 	Persoft Persona
1916 	udp 	persona 	Persoft Persona
1917 	tcp 	noagent 	nOAgent
1917 	udp 	noagent 	nOAgent
1918 	tcp 	can-nds 	IBM Tivole Directory Service – NDS
1918 	udp 	can-nds 	IBM Tivole Directory Service – NDS
1919 	tcp 	can-dch 	IBM Tivoli Directory Service – DCH
1919 	udp 	can-dch 	IBM Tivoli Directory Service – DCH
1920 	tcp 	can-ferret 	IBM Tivoli Directory Service – FERRET
1920 	udp 	can-ferret 	IBM Tivoli Directory Service – FERRET
1921 	tcp 	noadmin 	NoAdmin
1921 	udp 	noadmin 	NoAdmin
1922 	tcp 	tapestry 	Tapestry
1922 	udp 	tapestry 	Tapestry
1923 	tcp 	spice 	SPICE
1923 	udp 	spice 	SPICE
1924 	tcp 	xiip 	XIIP
1924 	udp 	xiip 	XIIP
1925 	tcp 	discovery-port 	Surrogate Discovery Port
1925 	udp 	discovery-port 	Surrogate Discovery Port
1926 	tcp 	egs 	Evolution Game Server
1926 	udp 	egs 	Evolution Game Server
1927 	tcp 	videte-cipc 	Videte CIPC Port
1927 	udp 	videte-cipc 	Videte CIPC Port
1928 	tcp 	emsd-port 	Expnd Maui Srvr Dscovr
1928 	udp 	emsd-port 	Expnd Maui Srvr Dscovr
1929 	tcp 	bandwiz-system 	Bandwiz System – Server
1929 	udp 	bandwiz-system 	Bandwiz System – Server
1930 	tcp 	driveappserver 	Drive AppServer
1930 	udp 	driveappserver 	Drive AppServer
1931 	tcp 	amdsched 	AMD SCHED
1931 	udp 	amdsched 	AMD SCHED
1932 	tcp 	ctt-broker 	CTT Broker
1932 	udp 	ctt-broker 	CTT Broker
1933 	tcp 	xmapi 	IBM LM MT Agent
1933 	udp 	xmapi 	IBM LM MT Agent
1934 	tcp 	xaapi 	IBM LM Appl Agent
1934 	udp 	xaapi 	IBM LM Appl Agent
1935 	tcp 	macromedia-fcs 	Macromedia Flash Communications Server MX
1935 	udp 	macromedia-fcs 	Macromedia Flash Communications server MX
1936 	tcp 	jetcmeserver 	JetCmeServer Server Port
1936 	udp 	jetcmeserver 	JetCmeServer Server Port
1937 	tcp 	jwserver 	JetVWay Server Port
1937 	udp 	jwserver 	JetVWay Server Port
1938 	tcp 	jwclient 	JetVWay Client Port
1938 	udp 	jwclient 	JetVWay Client Port
1939 	tcp 	jvserver 	JetVision Server Port
1939 	udp 	jvserver 	JetVision Server Port
1940 	tcp 	jvclient 	JetVision Client Port
1940 	udp 	jvclient 	JetVision Client Port
1941 	tcp 	dic-aida 	DIC-Aida
1941 	udp 	dic-aida 	DIC-Aida
1942 	tcp 	res 	Real Enterprise Service
1942 	udp 	res 	Real Enterprise Service
1943 	tcp 	beeyond-media 	Beeyond Media
1943 	udp 	beeyond-media 	Beeyond Media
1944 	tcp 	close-combat 	close-combat
1944 	udp 	close-combat 	close-combat
1945 	tcp 	dialogic-elmd 	dialogic-elmd
1945 	udp 	dialogic-elmd 	dialogic-elmd
1946 	tcp 	tekpls 	tekpls
1946 	udp 	tekpls 	tekpls
1947 	tcp 	sentinelsrm 	SentinelSRM
1947 	udp 	sentinelsrm 	SentinelSRM
1948 	tcp 	eye2eye 	eye2eye
1948 	udp 	eye2eye 	eye2eye
1949 	tcp 	ismaeasdaqlive 	ISMA Easdaq Live
1949 	udp 	ismaeasdaqlive 	ISMA Easdaq Live
1950 	tcp 	ismaeasdaqtest 	ISMA Easdaq Test
1950 	udp 	ismaeasdaqtest 	ISMA Easdaq Test
1951 	tcp 	bcs-lmserver 	bcs-lmserver
1951 	udp 	bcs-lmserver 	bcs-lmserver
1952 	tcp 	mpnjsc 	mpnjsc
1952 	udp 	mpnjsc 	mpnjsc
1953 	tcp 	rapidbase 	Rapid Base
1953 	udp 	rapidbase 	Rapid Base
1954 	tcp 	abr-api 	ABR-API (diskbridge)
1954 	udp 	abr-api 	ABR-API (diskbridge)
1955 	tcp 	abr-secure 	ABR-Secure Data (diskbridge)
1955 	udp 	abr-secure 	ABR-Secure Data (diskbridge)
1956 	tcp 	vrtl-vmf-ds 	Vertel VMF DS
1956 	udp 	vrtl-vmf-ds 	Vertel VMF DS
1957 	tcp 	unix-status 	unix-status
1957 	udp 	unix-status 	unix-status
1958 	tcp 	dxadmind 	CA Administration Daemon
1958 	udp 	dxadmind 	CA Administration Daemon
1959 	tcp 	simp-all 	SIMP Channel
1959 	udp 	simp-all 	SIMP Channel
1960 	tcp 	nasmanager 	Merit DAC NASmanager
1960 	udp 	nasmanager 	Merit DAC NASmanager
1961 	tcp 	bts-appserver 	BTS APPSERVER
1961 	udp 	bts-appserver 	BTS APPSERVER
1962 	tcp 	biap-mp 	BIAP-MP
1962 	udp 	biap-mp 	BIAP-MP
1963 	tcp 	webmachine 	WebMachine
1963 	udp 	webmachine 	WebMachine
1964 	tcp 	solid-e-engine 	SOLID E ENGINE
1964 	udp 	solid-e-engine 	SOLID E ENGINE
1965 	tcp 	tivoli-npm 	Tivoli NPM
1965 	udp 	tivoli-npm 	Tivoli NPM
1966 	tcp 	slush 	Slush
1966 	udp 	slush 	Slush
1967 	tcp 	sns-quote 	SNS Quote
1967 	udp 	sns-quote 	SNS Quote
1968 	tcp 	lipsinc 	LIPSinc
1968 	udp 	lipsinc 	LIPSinc
1969 	tcp 	lipsinc1 	LIPSinc 1
1969 	udp 	lipsinc1 	LIPSinc 1
1970 	tcp 	netop-rc 	NetOp Remote Control
1970 	udp 	netop-rc 	NetOp Remote Control
1971 	tcp 	netop-school 	NetOp School
1971 	udp 	netop-school 	NetOp School
1972 	tcp 	intersys-cache 	Cache
1972 	udp 	intersys-cache 	Cache
1973 	tcp 	dlsrap 	Data Link Switching Remote Access Protocol
1973 	udp 	dlsrap 	Data Link Switching Remote Access Protocol
1974 	tcp 	drp 	DRP
1974 	udp 	drp 	DRP
1975 	tcp 	tcoflashagent 	TCO Flash Agent
1975 	udp 	tcoflashagent 	TCO Flash Agent
1976 	tcp 	tcoregagent 	TCO Reg Agent
1976 	udp 	tcoregagent 	TCO Reg Agent
1977 	tcp 	tcoaddressbook 	TCO Address Book
1977 	udp 	tcoaddressbook 	TCO Address Book
1978 	tcp 	unisql 	UniSQL
1978 	udp 	unisql 	UniSQL
1979 	tcp 	unisql-java 	UniSQL Java
1979 	udp 	unisql-java 	UniSQL Java
1980 	tcp 	pearldoc-xact 	PearlDoc XACT
1980 	udp 	pearldoc-xact 	PearlDoc XACT
1981 	tcp 	p2pq 	p2pQ
1981 	udp 	p2pq 	p2pQ
1982 	tcp 	estamp 	Evidentiary Timestamp
1982 	udp 	estamp 	Evidentiary Timestamp
1983 	tcp 	lhtp 	Loophole Test Protocol
1983 	udp 	lhtp 	Loophole Test Protocol
1984 	tcp 	bb 	BB
1984 	udp 	bb 	BB
1985 	tcp 	hsrp 	Hot Standby Router Protocol
1985 	udp 	hsrp 	Hot Standby Router Protocol
1986 	tcp 	licensedaemon 	cisco license management
1986 	udp 	licensedaemon 	cisco license management
1987 	tcp 	tr-rsrb-p1 	cisco RSRB Priority 1 port
1987 	udp 	tr-rsrb-p1 	cisco RSRB Priority 1 port
1988 	tcp 	tr-rsrb-p2 	cisco RSRB Priority 2 port
1988 	udp 	tr-rsrb-p2 	cisco RSRB Priority 2 port
1989 	tcp 	tr-rsrb-p3 	cisco RSRB Priority 3 port
1989 	udp 	tr-rsrb-p3 	cisco RSRB Priority 3 port
1989 	tcp 	mshnet 	MHSnet system
1989 	udp 	mshnet 	MHSnet system
1990 	tcp 	stun-p1 	cisco STUN Priority 1 port
1990 	udp 	stun-p1 	cisco STUN Priority 1 port
1991 	tcp 	stun-p2 	cisco STUN Priority 2 port
1991 	udp 	stun-p2 	cisco STUN Priority 2 port
1992 	tcp 	stun-p3 	cisco STUN Priority 3 port
1992 	udp 	stun-p3 	cisco STUN Priority 3 port
1992 	tcp 	ipsendmsg 	IPsendmsg
1992 	udp 	ipsendmsg 	IPsendmsg
1993 	tcp 	snmp-tcp-port 	cisco SNMP TCP port
1993 	udp 	snmp-tcp-port 	cisco SNMP TCP port
1994 	tcp 	stun-port 	cisco serial tunnel port
1994 	udp 	stun-port 	cisco serial tunnel port
1995 	tcp 	perf-port 	cisco perf port
1995 	udp 	perf-port 	cisco perf port
1996 	tcp 	tr-rsrb-port 	cisco Remote SRB port
1996 	udp 	tr-rsrb-port 	cisco Remote SRB port
1997 	tcp 	gdp-port 	cisco Gateway Discovery Protocol
1997 	udp 	gdp-port 	cisco Gateway Discovery Protocol
1998 	tcp 	x25-svc-port 	cisco X.25 service (XOT)
1998 	udp 	x25-svc-port 	cisco X.25 service (XOT)
1999 	tcp 	tcp-id-port 	cisco identification port
1999 	udp 	tcp-id-port 	cisco identification port
2000 	tcp 	cisco-sccp 	Cisco SCCP
2000 	udp 	cisco-sccp 	Cisco SCCp
2001 	tcp 	dc 	
2001 	udp 	wizard 	curry
2002 	tcp 	globe 	
2002 	udp 	globe 	
2003 	tcp 	brutus 	Brutus Server
2003 	udp 	brutus 	Brutus Server
2004 	tcp 	mailbox 	
2004 	udp 	emce 	CCWS mm conf
2005 	tcp 	berknet 	
2005 	udp 	oracle 	
2006 	tcp 	invokator 	
2006 	udp 	raid-cd 	raid
2007 	tcp 	dectalk 	
2007 	udp 	raid-am 	
2008 	tcp 	conf 	
2008 	udp 	terminaldb 	
2009 	tcp 	news 	
2009 	udp 	whosockami 	
2010 	tcp 	search 	
2010 	udp 	pipe-server 	
2010 	udp 	pipe_server 	
2011 	tcp 	raid-cc 	raid
2011 	udp 	servserv 	
2012 	tcp 	ttyinfo 	
2012 	udp 	raid-ac 	
2013 	tcp 	raid-am 	
2013 	udp 	raid-cd 	
2014 	tcp 	troff 	
2014 	udp 	raid-sf 	
2015 	tcp 	cypress 	
2015 	udp 	raid-cs 	
2016 	tcp 	bootserver 	
2016 	udp 	bootserver 	
2017 	tcp 	cypress-stat 	
2017 	udp 	bootclient 	
2018 	tcp 	terminaldb 	
2018 	udp 	rellpack 	
2019 	tcp 	whosockami 	
2019 	udp 	about 	
2020 	tcp 	xinupageserver 	
2020 	udp 	xinupageserver 	
2021 	tcp 	servexec 	
2021 	udp 	xinuexpansion1 	
2022 	tcp 	down 	
2022 	udp 	xinuexpansion2 	
2023 	tcp 	xinuexpansion3 	
2023 	udp 	xinuexpansion3 	
2024 	tcp 	xinuexpansion4 	
2024 	udp 	xinuexpansion4 	
2025 	tcp 	ellpack 	
2025 	udp 	xribs 	
2026 	tcp 	scrabble 	
2026 	udp 	scrabble 	
2027 	tcp 	shadowserver 	
2027 	udp 	shadowserver 	
2028 	tcp 	submitserver 	
2028 	udp 	submitserver 	
2029 	tcp 	hsrpv6 	Hot Standby Router Protocol IPv6
2029 	udp 	hsrpv6 	Hot Standby Router Protocol IPv6
2030 	tcp 	device2 	
2030 	udp 	device2 	
2031 	tcp 	mobrien-chat 	mobrien-chat
2031 	udp 	mobrien-chat 	mobrien-chat
2032 	tcp 	blackboard 	
2032 	udp 	blackboard 	
2033 	tcp 	glogger 	
2033 	udp 	glogger 	
2034 	tcp 	scoremgr 	
2034 	udp 	scoremgr 	
2035 	tcp 	imsldoc 	
2035 	udp 	imsldoc 	
2036 	tcp 	e-dpnet 	Ethernet WS DP network
2036 	udp 	e-dpnet 	Ethernet WS DP network
2037 	tcp 	applus 	APplus Application Server
2037 	udp 	applus 	APplus Application Server
2038 	tcp 	objectmanager 	
2038 	udp 	objectmanager 	
2039 	tcp 	prizma 	Prizma Monitoring Service
2039 	udp 	prizma 	Prizma Monitoring Service
2040 	tcp 	lam 	
2040 	udp 	lam 	
2041 	tcp 	interbase 	
2041 	udp 	interbase 	
2042 	tcp 	isis 	isis
2042 	udp 	isis 	isis
2043 	tcp 	isis-bcast 	isis-bcast
2043 	udp 	isis-bcast 	isis-bcast
2044 	tcp 	rimsl 	
2044 	udp 	rimsl 	
2045 	tcp 	cdfunc 	
2045 	udp 	cdfunc 	
2046 	tcp 	sdfunc 	
2046 	udp 	sdfunc 	
2047 	tcp 	dls 	
2047 	udp 	dls 	
2048 	tcp 	dls-monitor 	
2048 	udp 	dls-monitor 	
2049 	tcp 	shilp 	
2049 	udp 	shilp 	
2049 	tcp 	nfs 	Network File System – Sun Microsystems
2049 	udp 	nfs 	Network File System – Sun Microsystems
2049 	sctp 	nfs 	Network File System
2050 	tcp 	av-emb-config 	Avaya EMB Config Port
2050 	udp 	av-emb-config 	Avaya EMB Config Port
2051 	tcp 	epnsdp 	EPNSDP
2051 	udp 	epnsdp 	EPNSDP
2052 	tcp 	clearvisn 	clearVisn Services Port
2052 	udp 	clearvisn 	clearVisn Services Port
2053 	tcp 	lot105-ds-upd 	Lot105 DSuper Updates
2053 	udp 	lot105-ds-upd 	Lot105 DSuper Updates
2054 	tcp 	weblogin 	Weblogin Port
2054 	udp 	weblogin 	Weblogin Port
2055 	tcp 	iop 	Iliad-Odyssey Protocol
2055 	udp 	iop 	Iliad-Odyssey Protocol
2056 	tcp 	omnisky 	OmniSky Port
2056 	udp 	omnisky 	OmniSky Port
2057 	tcp 	rich-cp 	Rich Content Protocol
2057 	udp 	rich-cp 	Rich Content Protocol
2058 	tcp 	newwavesearch 	NewWaveSearchables RMI
2058 	udp 	newwavesearch 	NewWaveSearchables RMI
2059 	tcp 	bmc-messaging 	BMC Messaging Service
2059 	udp 	bmc-messaging 	BMC Messaging Service
2060 	tcp 	teleniumdaemon 	Telenium Daemon IF
2060 	udp 	teleniumdaemon 	Telenium Daemon IF
2061 	tcp 	netmount 	NetMount
2061 	udp 	netmount 	NetMount
2062 	tcp 	icg-swp 	ICG SWP Port
2062 	udp 	icg-swp 	ICG SWP Port
2063 	tcp 	icg-bridge 	ICG Bridge Port
2063 	udp 	icg-bridge 	ICG Bridge Port
2064 	tcp 	icg-iprelay 	ICG IP Relay Port
2064 	udp 	icg-iprelay 	ICG IP Relay Port
2065 	tcp 	dlsrpn 	Data Link Switch Read Port Number
2065 	udp 	dlsrpn 	Data Link Switch Read Port Number
2066 	tcp 	aura 	AVM USB Remote Architecture
2066 	udp 	aura 	AVM USB Remote Architecture
2067 	tcp 	dlswpn 	Data Link Switch Write Port Number
2067 	udp 	dlswpn 	Data Link Switch Write Port Number
2068 	tcp 	avauthsrvprtcl 	Avocent AuthSrv Protocol
2068 	udp 	avauthsrvprtcl 	Avocent AuthSrv Protocol
2069 	tcp 	event-port 	HTTP Event Port
2069 	udp 	event-port 	HTTP Event Port
2070 	tcp 	ah-esp-encap 	AH and ESP Encapsulated in UDP packet
2070 	udp 	ah-esp-encap 	AH and ESP Encapsulated in UDP packet
2071 	tcp 	acp-port 	Axon Control Protocol
2071 	udp 	acp-port 	Axon Control Protocol
2072 	tcp 	msync 	GlobeCast mSync
2072 	udp 	msync 	GlobeCast mSync
2073 	tcp 	gxs-data-port 	DataReel Database Socket
2073 	udp 	gxs-data-port 	DataReel Database Socket
2074 	tcp 	vrtl-vmf-sa 	Vertel VMF SA
2074 	udp 	vrtl-vmf-sa 	Vertel VMF SA
2075 	tcp 	newlixengine 	Newlix ServerWare Engine
2075 	udp 	newlixengine 	Newlix ServerWare Engine
2076 	tcp 	newlixconfig 	Newlix JSPConfig
2076 	udp 	newlixconfig 	Newlix JSPConfig
2077 	tcp 	tsrmagt 	Old Tivoli Storage Manager
2077 	udp 	tsrmagt 	Old Tivoli Storage Manager
2078 	tcp 	tpcsrvr 	IBM Total Productivity Center Server
2078 	udp 	tpcsrvr 	IBM Total Productivity Center Server
2079 	tcp 	idware-router 	IDWARE Router Port
2079 	udp 	idware-router 	IDWARE Router Port
2080 	tcp 	autodesk-nlm 	Autodesk NLM (FLEXlm)
2080 	udp 	autodesk-nlm 	Autodesk NLM (FLEXlm)
2081 	tcp 	kme-trap-port 	KME PRINTER TRAP PORT
2081 	udp 	kme-trap-port 	KME PRINTER TRAP PORT
2082 	tcp 	infowave 	Infowave Mobility Server
2082 	udp 	infowave 	Infowave Mobility Server
2083 	tcp 	radsec 	Secure Radius Service
2083 	udp 	radsec 	Secure Radius Service
2084 	tcp 	sunclustergeo 	SunCluster Geographic
2084 	udp 	sunclustergeo 	SunCluster Geographic
2085 	tcp 	ada-cip 	ADA Control
2085 	udp 	ada-cip 	ADA Control
2086 	tcp 	gnunet 	GNUnet
2086 	udp 	gnunet 	GNUnet
2087 	tcp 	eli 	ELI – Event Logging Integration
2087 	udp 	eli 	ELI – Event Logging Integration
2088 	tcp 	ip-blf 	IP Busy Lamp Field
2088 	udp 	ip-blf 	IP Busy Lamp Field
2089 	tcp 	sep 	Security Encapsulation Protocol – SEP
2089 	udp 	sep 	Security Encapsulation Protocol – SEP
2090 	tcp 	lrp 	Load Report Protocol
2090 	udp 	lrp 	Load Report Protocol
2091 	tcp 	prp 	PRP
2091 	udp 	prp 	PRP
2092 	tcp 	descent3 	Descent 3
2092 	udp 	descent3 	Descent 3
2093 	tcp 	nbx-cc 	NBX CC
2093 	udp 	nbx-cc 	NBX CC
2094 	tcp 	nbx-au 	NBX AU
2094 	udp 	nbx-au 	NBX AU
2095 	tcp 	nbx-ser 	NBX SER
2095 	udp 	nbx-ser 	NBX SER
2096 	tcp 	nbx-dir 	NBX DIR
2096 	udp 	nbx-dir 	NBX DIR
2097 	tcp 	jetformpreview 	Jet Form Preview
2097 	udp 	jetformpreview 	Jet Form Preview
2098 	tcp 	dialog-port 	Dialog Port
2098 	udp 	dialog-port 	Dialog Port
2099 	tcp 	h2250-annex-g 	H.225.0 Annex G Signalling
2099 	udp 	h2250-annex-g 	H.225.0 Annex G Signalling
2100 	tcp 	amiganetfs 	Amiga Network Filesystem
2100 	udp 	amiganetfs 	Amiga Network Filesystem
2101 	tcp 	rtcm-sc104 	rtcm-sc104
2101 	udp 	rtcm-sc104 	rtcm-sc104
2102 	tcp 	zephyr-srv 	Zephyr server
2102 	udp 	zephyr-srv 	Zephyr server
2103 	tcp 	zephyr-clt 	Zephyr serv-hm connection
2103 	udp 	zephyr-clt 	Zephyr serv-hm connection
2104 	tcp 	zephyr-hm 	Zephyr hostmanager
2104 	udp 	zephyr-hm 	Zephyr hostmanager
2105 	tcp 	minipay 	MiniPay
2105 	udp 	minipay 	MiniPay
2106 	tcp 	mzap 	MZAP
2106 	udp 	mzap 	MZAP
2107 	tcp 	bintec-admin 	BinTec Admin
2107 	udp 	bintec-admin 	BinTec Admin
2108 	tcp 	comcam 	Comcam
2108 	udp 	comcam 	Comcam
2109 	tcp 	ergolight 	Ergolight
2109 	udp 	ergolight 	Ergolight
2110 	tcp 	umsp 	UMSP
2110 	udp 	umsp 	UMSP
2111 	tcp 	dsatp 	OPNET Dynamic Sampling Agent Transaction Prot
2111 	udp 	dsatp 	OPNET Dynamic Sampling Agent Transaction Prot
2112 	tcp 	idonix-metanet 	Idonix MetaNet
2112 	udp 	idonix-metanet 	Idonix MetaNet
2113 	tcp 	hsl-storm 	HSL StoRM
2113 	udp 	hsl-storm 	HSL StoRM
2114 	tcp 	newheights 	NEWHEIGHTS
2114 	udp 	newheights 	NEWHEIGHTS
2115 	tcp 	kdm 	Key Distribution Manager
2115 	udp 	kdm 	Key Distribution Manager
2116 	tcp 	ccowcmr 	CCOWCMR
2116 	udp 	ccowcmr 	CCOWCMR
2117 	tcp 	mentaclient 	MENTACLIENT
2117 	udp 	mentaclient 	MENTACLIENT
2118 	tcp 	mentaserver 	MENTASERVER
2118 	udp 	mentaserver 	MENTASERVER
2119 	tcp 	gsigatekeeper 	GSIGATEKEEPER
2119 	udp 	gsigatekeeper 	GSIGATEKEEPER
2120 	tcp 	qencp 	Quick Eagle Networks CP
2120 	udp 	qencp 	Quick Eagle Networks CP
2121 	tcp 	scientia-ssdb 	SCIENTIA-SSDB
2121 	udp 	scientia-ssdb 	SCIENTIA-SSDB
2122 	tcp 	caupc-remote 	CauPC Remote Control
2122 	udp 	caupc-remote 	CauPC Remote Control
2123 	tcp 	gtp-control 	GTP-Control Plane (3GPP)
2123 	udp 	gtp-control 	GTP-Control Plane (3GPP)
2124 	tcp 	elatelink 	ELATELINK
2124 	udp 	elatelink 	ELATELINK
2125 	tcp 	lockstep 	LOCKSTEP
2125 	udp 	lockstep 	LOCKSTEP
2126 	tcp 	pktcable-cops 	PktCable-COPS
2126 	udp 	pktcable-cops 	PktCable-COPS
2127 	tcp 	index-pc-wb 	INDEX-PC-WB
2127 	udp 	index-pc-wb 	INDEX-PC-WB
2128 	tcp 	net-steward 	Net Steward Control
2128 	udp 	net-steward 	Net Steward Control
2129 	tcp 	cs-live 	cs-live.com
2129 	udp 	cs-live 	cs-live.com
2130 	tcp 	xds 	XDS
2130 	udp 	xds 	XDS
2131 	tcp 	avantageb2b 	Avantageb2b
2131 	udp 	avantageb2b 	Avantageb2b
2132 	tcp 	solera-epmap 	SoleraTec End Point Map
2132 	udp 	solera-epmap 	SoleraTec End Point Map
2133 	tcp 	zymed-zpp 	ZYMED-ZPP
2133 	udp 	zymed-zpp 	ZYMED-ZPP
2134 	tcp 	avenue 	AVENUE
2134 	udp 	avenue 	AVENUE
2135 	tcp 	gris 	Grid Resource Information Server
2135 	udp 	gris 	Grid Resource Information Server
2136 	tcp 	appworxsrv 	APPWORXSRV
2136 	udp 	appworxsrv 	APPWORXSRV
2137 	tcp 	connect 	CONNECT
2137 	udp 	connect 	CONNECT
2138 	tcp 	unbind-cluster 	UNBIND-CLUSTER
2138 	udp 	unbind-cluster 	UNBIND-CLUSTER
2139 	tcp 	ias-auth 	IAS-AUTH
2139 	udp 	ias-auth 	IAS-AUTH
2140 	tcp 	ias-reg 	IAS-REG
2140 	udp 	ias-reg 	IAS-REG
2141 	tcp 	ias-admind 	IAS-ADMIND
2141 	udp 	ias-admind 	IAS-ADMIND
2142 	tcp 	tdmoip 	TDM OVER IP
2142 	udp 	tdmoip 	TDM OVER IP
2143 	tcp 	lv-jc 	Live Vault Job Control
2143 	udp 	lv-jc 	Live Vault Job Control
2144 	tcp 	lv-ffx 	Live Vault Fast Object Transfer
2144 	udp 	lv-ffx 	Live Vault Fast Object Transfer
2145 	tcp 	lv-pici 	Live Vault Remote Diagnostic Console Support
2145 	udp 	lv-pici 	Live Vault Remote Diagnostic Console Support
2146 	tcp 	lv-not 	Live Vault Admin Event Notification
2146 	udp 	lv-not 	Live Vault Admin Event Notification
2147 	tcp 	lv-auth 	Live Vault Authentication
2147 	udp 	lv-auth 	Live Vault Authentication
2148 	tcp 	veritas-ucl 	VERITAS UNIVERSAL COMMUNICATION LAYER
2148 	udp 	veritas-ucl 	VERITAS UNIVERSAL COMMUNICATION LAYER
2149 	tcp 	acptsys 	ACPTSYS
2149 	udp 	acptsys 	ACPTSYS
2150 	tcp 	dynamic3d 	DYNAMIC3D
2150 	udp 	dynamic3d 	DYNAMIC3D
2151 	tcp 	docent 	DOCENT
2151 	udp 	docent 	DOCENT
2152 	tcp 	gtp-user 	GTP-User Plane (3GPP)
2152 	udp 	gtp-user 	GTP-User Plane (3GPP)
2153 	tcp 	ctlptc 	Control Protocol
2153 	udp 	ctlptc 	Control Protocol
2154 	tcp 	stdptc 	Standard Protocol
2154 	udp 	stdptc 	Standard Protocol
2155 	tcp 	brdptc 	Bridge Protocol
2155 	udp 	brdptc 	Bridge Protocol
2156 	tcp 	trp 	Talari Reliable Protocol
2156 	udp 	trp 	Talari Reliable Protocol
2157 	tcp 	xnds 	Xerox Network Document Scan Protocol
2157 	udp 	xnds 	Xerox Network Document Scan Protocol
2158 	tcp 	touchnetplus 	TouchNetPlus Service
2158 	udp 	touchnetplus 	TouchNetPlus Service
2159 	tcp 	gdbremote 	GDB Remote Debug Port
2159 	udp 	gdbremote 	GDB Remote Debug Port
2160 	tcp 	apc-2160 	APC 2160
2160 	udp 	apc-2160 	APC 2160
2161 	tcp 	apc-2161 	APC 2161
2161 	udp 	apc-2161 	APC 2161
2162 	tcp 	navisphere 	Navisphere
2162 	udp 	navisphere 	Navisphere
2163 	tcp 	navisphere-sec 	Navisphere Secure
2163 	udp 	navisphere-sec 	Navisphere Secure
2164 	tcp 	ddns-v3 	Dynamic DNS Version 3
2164 	udp 	ddns-v3 	Dynamic DNS Version 3
2165 	tcp 	x-bone-api 	X-Bone API
2165 	udp 	x-bone-api 	X-Bone API
2166 	tcp 	iwserver 	iwserver
2166 	udp 	iwserver 	iwserver
2167 	tcp 	raw-serial 	Raw Async Serial Link
2167 	udp 	raw-serial 	Raw Async Serial Link
2168 	tcp 	easy-soft-mux 	easy-soft Multiplexer
2168 	udp 	easy-soft-mux 	easy-soft Multiplexer
2169 	tcp 	brain 	Backbone for Academic Information Notification
2169 	udp 	brain 	Backbone for Academic Information Notification
2170 	tcp 	eyetv 	EyeTV Server Port
2170 	udp 	eyetv 	EyeTV Server Port
2171 	tcp 	msfw-storage 	MS Firewall Storage
2171 	udp 	msfw-storage 	MS Firewall Storage
2172 	tcp 	msfw-s-storage 	MS Firewall SecureStorage
2172 	udp 	msfw-s-storage 	MS Firewall SecureStorage
2173 	tcp 	msfw-replica 	MS Firewall Replication
2173 	udp 	msfw-replica 	MS Firewall Replication
2174 	tcp 	msfw-array 	MS Firewall Intra Array
2174 	udp 	msfw-array 	MS Firewall Intra Array
2175 	tcp 	airsync 	Microsoft Desktop AirSync Protocol
2175 	udp 	airsync 	Microsoft Desktop AirSync Protocol
2176 	tcp 	rapi 	Microsoft ActiveSync Remote API
2176 	udp 	rapi 	Microsoft ActiveSync Remote API
2177 	tcp 	qwave 	qWAVE Bandwidth Estimate
2177 	udp 	qwave 	qWAVE Bandwidth Estimate
2178 	tcp 	bitspeer 	Peer Services for BITS
2178 	udp 	bitspeer 	Peer Services for BITS
2179 	tcp 	vmrdp 	Microsoft RDP for virtual machines
2179 	udp 	vmrdp 	Microsoft RDP for virtual machines
2180 	tcp 	mc-gt-srv 	Millicent Vendor Gateway Server
2180 	udp 	mc-gt-srv 	Millicent Vendor Gateway Server
2181 	tcp 	eforward 	eforward
2181 	udp 	eforward 	eforward
2182 	tcp 	cgn-stat 	CGN status
2182 	udp 	cgn-stat 	CGN status
2183 	tcp 	cgn-config 	Code Green configuration
2183 	udp 	cgn-config 	Code Green configuration
2184 	tcp 	nvd 	NVD User
2184 	udp 	nvd 	NVD User
2185 	tcp 	onbase-dds 	OnBase Distributed Disk Services
2185 	udp 	onbase-dds 	OnBase Distributed Disk Services
2186 	tcp 	gtaua 	Guy-Tek Automated Update Applications
2186 	udp 	gtaua 	Guy-Tek Automated Update Applications
2187 	tcp 	ssmc 	Sepehr System Management Control
2187 	udp 	ssmd 	Sepehr System Management Data
2188 	tcp 	radware-rpm 	Radware Resource Pool Manager
2188 	udp 		Reserved
2189 	tcp 	radware-rpm-s 	Secure Radware Resource Pool Manager
2189 	udp 		Reserved
2190 	tcp 	tivoconnect 	TiVoConnect Beacon
2190 	udp 	tivoconnect 	TiVoConnect Beacon
2191 	tcp 	tvbus 	TvBus Messaging
2191 	udp 	tvbus 	TvBus Messaging
2192 	tcp 	asdis 	ASDIS software management
2192 	udp 	asdis 	ASDIS software management
2193 	tcp 	drwcs 	Dr.Web Enterprise Management Service
2193 	udp 	drwcs 	Dr.Web Enterprise Management Service
2194-2196 		Unassigned
2197 	tcp 	mnp-exchange 	MNP data exchange
2197 	udp 	mnp-exchange 	MNP data exchange
2198 	tcp 	onehome-remote 	OneHome Remote Access
2198 	udp 	onehome-remote 	OneHome Remote Access
2199 	tcp 	onehome-help 	OneHome Service Port
2199 	udp 	onehome-help 	OneHome Service Port
2200 	tcp 	ici 	ICI
2200 	udp 	ici 	ICI
2201 	tcp 	ats 	Advanced Training System Program
2201 	udp 	ats 	Advanced Training System Program
2202 	tcp 	imtc-map 	Int. Multimedia Teleconferencing Cosortium
2202 	udp 	imtc-map 	Int. Multimedia Teleconferencing Cosortium
2203 	tcp 	b2-runtime 	b2 Runtime Protocol
2203 	udp 	b2-runtime 	b2 Runtime Protocol
2204 	tcp 	b2-license 	b2 License Server
2204 	udp 	b2-license 	b2 License Server
2205 	tcp 	jps 	Java Presentation Server
2205 	udp 	jps 	Java Presentation Server
2206 	tcp 	hpocbus 	HP OpenCall bus
2206 	udp 	hpocbus 	HP OpenCall bus
2207 	tcp 	hpssd 	HP Status and Services
2207 	udp 	hpssd 	HP Status and Services
2208 	tcp 	hpiod 	HP I/O Backend
2208 	udp 	hpiod 	HP I/O Backend
2209 	tcp 	rimf-ps 	HP RIM for Files Portal Service
2209 	udp 	rimf-ps 	HP RIM for Files Portal Service
2210 	tcp 	noaaport 	NOAAPORT Broadcast Network
2210 	udp 	noaaport 	NOAAPORT Broadcast Network
2211 	tcp 	emwin 	EMWIN
2211 	udp 	emwin 	EMWIN
2212 	tcp 	leecoposserver 	LeeCO POS Server Service
2212 	udp 	leecoposserver 	LeeCO POS Server Service
2213 	tcp 	kali 	Kali
2213 	udp 	kali 	Kali
2214 	tcp 	rpi 	RDQ Protocol Interface
2214 	udp 	rpi 	RDQ Protocol Interface
2215 	tcp 	ipcore 	IPCore.co.za GPRS
2215 	udp 	ipcore 	IPCore.co.za GPRS
2216 	tcp 	vtu-comms 	VTU data service
2216 	udp 	vtu-comms 	VTU data service
2217 	tcp 	gotodevice 	GoToDevice Device Management
2217 	udp 	gotodevice 	GoToDevice Device Management
2218 	tcp 	bounzza 	Bounzza IRC Proxy
2218 	udp 	bounzza 	Bounzza IRC Proxy
2219 	tcp 	netiq-ncap 	NetIQ NCAP Protocol
2219 	udp 	netiq-ncap 	NetIQ NCAP Protocol
2220 	tcp 	netiq 	NetIQ End2End
2220 	udp 	netiq 	NetIQ End2End
2221 	tcp 	ethernet-ip-s 	EtherNet/IP over TLS
2221 	udp 	ethernet-ip-s 	EtherNet/IP over DTLS
2222 	tcp 	EtherNet-IP-1 	EtherNet/IP I/O
IANA assigned this well-formed service name as a replacement for “EtherNet/IP-1”.
2222 	tcp 	EtherNet/IP-1 	EtherNet/IP I/O
2222 	udp 	EtherNet-IP-1 	EtherNet/IP I/O
IANA assigned this well-formed service name as a replacement for “EtherNet/IP-1”.
2222 	udp 	EtherNet/IP-1 	EtherNet/IP I/O
2223 	tcp 	rockwell-csp2 	Rockwell CSP2
2223 	udp 	rockwell-csp2 	Rockwell CSP2
2224 	tcp 	efi-mg 	Easy Flexible Internet/Multiplayer Games
2224 	udp 	efi-mg 	Easy Flexible Internet/Multiplayer Games
2225 	tcp 	rcip-itu 	Resource Connection Initiation Protocol
2225 	udp 		Reserved
2225 	sctp 	rcip-itu 	Resource Connection Initiation Protocol
2226 	tcp 	di-drm 	Digital Instinct DRM
2226 	udp 	di-drm 	Digital Instinct DRM
2227 	tcp 	di-msg 	DI Messaging Service
2227 	udp 	di-msg 	DI Messaging Service
2228 	tcp 	ehome-ms 	eHome Message Server
2228 	udp 	ehome-ms 	eHome Message Server
2229 	tcp 	datalens 	DataLens Service
2229 	udp 	datalens 	DataLens Service
2230 	tcp 	queueadm 	MetaSoft Job Queue Administration Service
2230 	udp 	queueadm 	MetaSoft Job Queue Administration Service
2231 	tcp 	wimaxasncp 	WiMAX ASN Control Plane Protocol
2231 	udp 	wimaxasncp 	WiMAX ASN Control Plane Protocol
2232 	tcp 	ivs-video 	IVS Video default
2232 	udp 	ivs-video 	IVS Video default
2233 	tcp 	infocrypt 	INFOCRYPT
2233 	udp 	infocrypt 	INFOCRYPT
2234 	tcp 	directplay 	DirectPlay
2234 	udp 	directplay 	DirectPlay
2235 	tcp 	sercomm-wlink 	Sercomm-WLink
2235 	udp 	sercomm-wlink 	Sercomm-WLink
2236 	tcp 	nani 	Nani
2236 	udp 	nani 	Nani
2237 	tcp 	optech-port1-lm 	Optech Port1 License Manager
2237 	udp 	optech-port1-lm 	Optech Port1 License Manager
2238 	tcp 	aviva-sna 	AVIVA SNA SERVER
2238 	udp 	aviva-sna 	AVIVA SNA SERVER
2239 	tcp 	imagequery 	Image Query
2239 	udp 	imagequery 	Image Query
2240 	tcp 	recipe 	RECIPe
2240 	udp 	recipe 	RECIPe
2241 	tcp 	ivsd 	IVS Daemon
2241 	udp 	ivsd 	IVS Daemon
2242 	tcp 	foliocorp 	Folio Remote Server
2242 	udp 	foliocorp 	Folio Remote Server
2243 	tcp 	magicom 	Magicom Protocol
2243 	udp 	magicom 	Magicom Protocol
2244 	tcp 	nmsserver 	NMS Server
2244 	udp 	nmsserver 	NMS Server
2245 	tcp 	hao 	HaO
2245 	udp 	hao 	HaO
2246 	tcp 	pc-mta-addrmap 	PacketCable MTA Addr Map
2246 	udp 	pc-mta-addrmap 	PacketCable MTA Addr Map
2247 	tcp 	antidotemgrsvr 	Antidote Deployment Manager Service
2247 	udp 	antidotemgrsvr 	Antidote Deployment Manager Service
2248 	tcp 	ums 	User Management Service
2248 	udp 	ums 	User Management Service
2249 	tcp 	rfmp 	RISO File Manager Protocol
2249 	udp 	rfmp 	RISO File Manager Protocol
2250 	tcp 	remote-collab 	remote-collab
2250 	udp 	remote-collab 	remote-collab
2251 	tcp 	dif-port 	Distributed Framework Port
2251 	udp 	dif-port 	Distributed Framework Port
2252 	tcp 	njenet-ssl 	NJENET using SSL
2252 	udp 	njenet-ssl 	NJENET using SSL
2253 	tcp 	dtv-chan-req 	DTV Channel Request
2253 	udp 	dtv-chan-req 	DTV Channel Request
2254 	tcp 	seispoc 	Seismic P.O.C. Port
2254 	udp 	seispoc 	Seismic P.O.C. Port
2255 	tcp 	vrtp 	VRTP – ViRtue Transfer Protocol
2255 	udp 	vrtp 	VRTP – ViRtue Transfer Protocol
2256 	tcp 	pcc-mfp 	PCC MFP
2256 	udp 	pcc-mfp 	PCC MFP
2257 	tcp 	simple-tx-rx 	simple text/file transfer
2257 	udp 	simple-tx-rx 	simple text/file transfer
2258 	tcp 	rcts 	Rotorcraft Communications Test System
2258 	udp 	rcts 	Rotorcraft Communications Test System
2259 			Unassigned
2260 	tcp 	apc-2260 	APC 2260
2260 	udp 	apc-2260 	APC 2260
2261 	tcp 	comotionmaster 	CoMotion Master Server
2261 	udp 	comotionmaster 	CoMotion Master Server
2262 	tcp 	comotionback 	CoMotion Backup Server
2262 	udp 	comotionback 	CoMotion Backup Server
2263 	tcp 	ecwcfg 	ECweb Configuration Service
2263 	udp 	ecwcfg 	ECweb Configuration Service
2264 	tcp 	apx500api-1 	Audio Precision Apx500 API Port 1
2264 	udp 	apx500api-1 	Audio Precision Apx500 API Port 1
2265 	tcp 	apx500api-2 	Audio Precision Apx500 API Port 2
2265 	udp 	apx500api-2 	Audio Precision Apx500 API Port 2
2266 	tcp 	mfserver 	M-Files Server
2266 	udp 	mfserver 	M-files Server
2267 	tcp 	ontobroker 	OntoBroker
2267 	udp 	ontobroker 	OntoBroker
2268 	tcp 	amt 	AMT
2268 	udp 	amt 	AMT
2269 	tcp 	mikey 	MIKEY
2269 	udp 	mikey 	MIKEY
2270 	tcp 	starschool 	starSchool
2270 	udp 	starschool 	starSchool
2271 	tcp 	mmcals 	Secure Meeting Maker Scheduling
2271 	udp 	mmcals 	Secure Meeting Maker Scheduling
2272 	tcp 	mmcal 	Meeting Maker Scheduling
2272 	udp 	mmcal 	Meeting Maker Scheduling
2273 	tcp 	mysql-im 	MySQL Instance Manager
2273 	udp 	mysql-im 	MySQL Instance Manager
2274 	tcp 	pcttunnell 	PCTTunneller
2274 	udp 	pcttunnell 	PCTTunneller
2275 	tcp 	ibridge-data 	iBridge Conferencing
2275 	udp 	ibridge-data 	iBridge Conferencing
2276 	tcp 	ibridge-mgmt 	iBridge Management
2276 	udp 	ibridge-mgmt 	iBridge Management
2277 	tcp 	bluectrlproxy 	Bt device control proxy
2277 	udp 	bluectrlproxy 	Bt device control proxy
2278 	tcp 	s3db 	Simple Stacked Sequences Database
2278 	udp 	s3db 	Simple Stacked Sequences Database
2279 	tcp 	xmquery 	xmquery
2279 	udp 	xmquery 	xmquery
2280 	tcp 	lnvpoller 	LNVPOLLER
2280 	udp 	lnvpoller 	LNVPOLLER
2281 	tcp 	lnvconsole 	LNVCONSOLE
2281 	udp 	lnvconsole 	LNVCONSOLE
2282 	tcp 	lnvalarm 	LNVALARM
2282 	udp 	lnvalarm 	LNVALARM
2283 	tcp 	lnvstatus 	LNVSTATUS
2283 	udp 	lnvstatus 	LNVSTATUS
2284 	tcp 	lnvmaps 	LNVMAPS
2284 	udp 	lnvmaps 	LNVMAPS
2285 	tcp 	lnvmailmon 	LNVMAILMON
2285 	udp 	lnvmailmon 	LNVMAILMON
2286 	tcp 	nas-metering 	NAS-Metering
2286 	udp 	nas-metering 	NAS-Metering
2287 	tcp 	dna 	DNA
2287 	udp 	dna 	DNA
2288 	tcp 	netml 	NETML
2288 	udp 	netml 	NETML
2289 	tcp 	dict-lookup 	Lookup dict server
2289 	udp 	dict-lookup 	Lookup dict server
2290 	tcp 	sonus-logging 	Sonus Logging Services
2290 	udp 	sonus-logging 	Sonus Logging Services
2291 	tcp 	eapsp 	EPSON Advanced Printer Share Protocol
2291 	udp 	eapsp 	EPSON Advanced Printer Share Protocol
2292 	tcp 	mib-streaming 	Sonus Element Management Services
2292 	udp 	mib-streaming 	Sonus Element Management Services
2293 	tcp 	npdbgmngr 	Network Platform Debug Manager
2293 	udp 	npdbgmngr 	Network Platform Debug Manager
2294 	tcp 	konshus-lm 	Konshus License Manager (FLEX)
2294 	udp 	konshus-lm 	Konshus License Manager (FLEX)
2295 	tcp 	advant-lm 	Advant License Manager
2295 	udp 	advant-lm 	Advant License Manager
2296 	tcp 	theta-lm 	Theta License Manager (Rainbow)
2296 	udp 	theta-lm 	Theta License Manager (Rainbow)
2297 	tcp 	d2k-datamover1 	D2K DataMover 1
2297 	udp 	d2k-datamover1 	D2K DataMover 1
2298 	tcp 	d2k-datamover2 	D2K DataMover 2
2298 	udp 	d2k-datamover2 	D2K DataMover 2
2299 	tcp 	pc-telecommute 	PC Telecommute
2299 	udp 	pc-telecommute 	PC Telecommute
2300 	tcp 	cvmmon 	CVMMON
2300 	udp 	cvmmon 	CVMMON
2301 	tcp 	cpq-wbem 	Compaq HTTP
2301 	udp 	cpq-wbem 	Compaq HTTP
2302 	tcp 	binderysupport 	Bindery Support
2302 	udp 	binderysupport 	Bindery Support
2303 	tcp 	proxy-gateway 	Proxy Gateway
2303 	udp 	proxy-gateway 	Proxy Gateway
2304 	tcp 	attachmate-uts 	Attachmate UTS
2304 	udp 	attachmate-uts 	Attachmate UTS
2305 	tcp 	mt-scaleserver 	MT ScaleServer
2305 	udp 	mt-scaleserver 	MT ScaleServer
2306 	tcp 	tappi-boxnet 	TAPPI BoxNet
2306 	udp 	tappi-boxnet 	TAPPI BoxNet
2307 	tcp 	pehelp 	pehelp
2307 	udp 	pehelp 	pehelp
2308 	tcp 	sdhelp 	sdhelp
2308 	udp 	sdhelp 	sdhelp
2309 	tcp 	sdserver 	SD Server
2309 	udp 	sdserver 	SD Server
2310 	tcp 	sdclient 	SD Client
2310 	udp 	sdclient 	SD Client
2311 	tcp 	messageservice 	Message Service
2311 	udp 	messageservice 	Message Service
2312 	tcp 	wanscaler 	WANScaler Communication Service
2312 	udp 	wanscaler 	WANScaler Communication Service
2313 	tcp 	iapp 	IAPP (Inter Access Point Protocol)
2313 	udp 	iapp 	IAPP (Inter Access Point Protocol)
2314 	tcp 	cr-websystems 	CR WebSystems
2314 	udp 	cr-websystems 	CR WebSystems
2315 	tcp 	precise-sft 	Precise Sft.
2315 	udp 	precise-sft 	Precise Sft.
2316 	tcp 	sent-lm 	SENT License Manager
2316 	udp 	sent-lm 	SENT License Manager
2317 	tcp 	attachmate-g32 	Attachmate G32
2317 	udp 	attachmate-g32 	Attachmate G32
2318 	tcp 	cadencecontrol 	Cadence Control
2318 	udp 	cadencecontrol 	Cadence Control
2319 	tcp 	infolibria 	InfoLibria
2319 	udp 	infolibria 	InfoLibria
2320 	tcp 	siebel-ns 	Siebel NS
2320 	udp 	siebel-ns 	Siebel NS
2321 	tcp 	rdlap 	RDLAP
2321 	udp 	rdlap 	RDLAP
2322 	tcp 	ofsd 	ofsd
2322 	udp 	ofsd 	ofsd
2323 	tcp 	3d-nfsd 	3d-nfsd
2323 	udp 	3d-nfsd 	3d-nfsd
2324 	tcp 	cosmocall 	Cosmocall
2324 	udp 	cosmocall 	Cosmocall
2325 	tcp 	ansysli 	ANSYS Licensing Interconnect
2325 	udp 	ansysli 	ANSYS Licensing Interconnect
2326 	tcp 	idcp 	IDCP
2326 	udp 	idcp 	IDCP
2327 	tcp 	xingcsm 	xingcsm
2327 	udp 	xingcsm 	xingcsm
2328 	tcp 	netrix-sftm 	Netrix SFTM
2328 	udp 	netrix-sftm 	Netrix SFTM
2329 	tcp 	nvd 	NVD
2329 	udp 	nvd 	NVD
2330 	tcp 	tscchat 	TSCCHAT
2330 	udp 	tscchat 	TSCCHAT
2331 	tcp 	agentview 	AGENTVIEW
2331 	udp 	agentview 	AGENTVIEW
2332 	tcp 	rcc-host 	RCC Host
2332 	udp 	rcc-host 	RCC Host
2333 	tcp 	snapp 	SNAPP
2333 	udp 	snapp 	SNAPP
2334 	tcp 	ace-client 	ACE Client Auth
2334 	udp 	ace-client 	ACE Client Auth
2335 	tcp 	ace-proxy 	ACE Proxy
2335 	udp 	ace-proxy 	ACE Proxy
2336 	tcp 	appleugcontrol 	Apple UG Control
2336 	udp 	appleugcontrol 	Apple UG Control
2337 	tcp 	ideesrv 	ideesrv
2337 	udp 	ideesrv 	ideesrv
2338 	tcp 	norton-lambert 	Norton Lambert
2338 	udp 	norton-lambert 	Norton Lambert
2339 	tcp 	3com-webview 	3Com WebView
2339 	udp 	3com-webview 	3Com WebView
2340 	tcp 	wrs-registry 	WRS Registry
IANA assigned this well-formed service name as a replacement for “wrs_registry”.
2340 	tcp 	wrs_registry 	WRS Registry
2340 	udp 	wrs-registry 	WRS Registry
IANA assigned this well-formed service name as a replacement for “wrs_registry”.
2340 	udp 	wrs_registry 	WRS Registry
2341 	tcp 	xiostatus 	XIO Status
2341 	udp 	xiostatus 	XIO Status
2342 	tcp 	manage-exec 	Seagate Manage Exec
2342 	udp 	manage-exec 	Seagate Manage Exec
2343 	tcp 	nati-logos 	nati logos
2343 	udp 	nati-logos 	nati logos
2344 	tcp 	fcmsys 	fcmsys
2344 	udp 	fcmsys 	fcmsys
2345 	tcp 	dbm 	dbm
2345 	udp 	dbm 	dbm
2346 	tcp 	redstorm-join 	Game Connection Port
IANA assigned this well-formed service name as a replacement for “redstorm_join”.
2346 	tcp 	redstorm_join 	Game Connection Port
2346 	udp 	redstorm-join 	Game Connection Port
IANA assigned this well-formed service name as a replacement for “redstorm_join”.
2346 	udp 	redstorm_join 	Game Connection Port
2347 	tcp 	redstorm-find 	Game Announcement and Location
IANA assigned this well-formed service name as a replacement for “redstorm_find”.
2347 	tcp 	redstorm_find 	Game Announcement and Location
2347 	udp 	redstorm-find 	Game Announcement and Location
IANA assigned this well-formed service name as a replacement for “redstorm_find”.
2347 	udp 	redstorm_find 	Game Announcement and Location
2348 	tcp 	redstorm-info 	Information to query for game status
IANA assigned this well-formed service name as a replacement for “redstorm_info”.
2348 	tcp 	redstorm_info 	Information to query for game status
2348 	udp 	redstorm-info 	Information to query for game status
IANA assigned this well-formed service name as a replacement for “redstorm_info”.
2348 	udp 	redstorm_info 	Information to query for game status
2349 	tcp 	redstorm-diag 	Diagnostics Port
IANA assigned this well-formed service name as a replacement for “redstorm_diag”.
2349 	tcp 	redstorm_diag 	Diagnostics Port
2349 	udp 	redstorm-diag 	Diagnostics Port
IANA assigned this well-formed service name as a replacement for “redstorm_diag”.
2349 	udp 	redstorm_diag 	Diagnostics Port
2350 	tcp 	psbserver 	Pharos Booking Server
2350 	udp 	psbserver 	Pharos Booking Server
2351 	tcp 	psrserver 	psrserver
2351 	udp 	psrserver 	psrserver
2352 	tcp 	pslserver 	pslserver
2352 	udp 	pslserver 	pslserver
2353 	tcp 	pspserver 	pspserver
2353 	udp 	pspserver 	pspserver
2354 	tcp 	psprserver 	psprserver
2354 	udp 	psprserver 	psprserver
2355 	tcp 	psdbserver 	psdbserver
2355 	udp 	psdbserver 	psdbserver
2356 	tcp 	gxtelmd 	GXT License Managemant
2356 	udp 	gxtelmd 	GXT License Managemant
2357 	tcp 	unihub-server 	UniHub Server
2357 	udp 	unihub-server 	UniHub Server
2358 	tcp 	futrix 	Futrix
2358 	udp 	futrix 	Futrix
2359 	tcp 	flukeserver 	FlukeServer
2359 	udp 	flukeserver 	FlukeServer
2360 	tcp 	nexstorindltd 	NexstorIndLtd
2360 	udp 	nexstorindltd 	NexstorIndLtd
2361 	tcp 	tl1 	TL1
2361 	udp 	tl1 	TL1
2362 	tcp 	digiman 	digiman
2362 	udp 	digiman 	digiman
2363 	tcp 	mediacntrlnfsd 	Media Central NFSD
2363 	udp 	mediacntrlnfsd 	Media Central NFSD
2364 	tcp 	oi-2000 	OI-2000
2364 	udp 	oi-2000 	OI-2000
2365 	tcp 	dbref 	dbref
2365 	udp 	dbref 	dbref
2366 	tcp 	qip-login 	qip-login
2366 	udp 	qip-login 	qip-login
2367 	tcp 	service-ctrl 	Service Control
2367 	udp 	service-ctrl 	Service Control
2368 	tcp 	opentable 	OpenTable
2368 	udp 	opentable 	OpenTable
2369 			Unassigned
2370 	tcp 	l3-hbmon 	L3-HBMon
2370 	udp 	l3-hbmon 	L3-HBMon
2371 	tcp 	hp-rda 	HP Remote Device Access
2371 	udp 		Reserved
2372 	tcp 	lanmessenger 	LanMessenger
2372 	udp 	lanmessenger 	LanMessenger
2373 	tcp 	remographlm 	Remograph License Manager
2373 	udp 		Reserved
2374 	tcp 	hydra 	Hydra RPC
2374 	udp 		Reserved
2375 	tcp 	docker 	Docker REST API (plain text)
2375 	udp 		Reserved
2376 	tcp 	docker-s 	Docker REST API (ssl)
2377 	tcp 	swarm 	RPC interface for Docker Swarm
2377 	udp 		Reserved
2378 			Unassigned
2379 	tcp 	etcd-client 	etcd client communication
2379 	udp 		Reserved
2380 	tcp 	etcd-server 	etcd server to server communication
2380 	udp 		Reserved
2381 	tcp 	compaq-https 	Compaq HTTPS
2381 	udp 	compaq-https 	Compaq HTTPS
2382 	tcp 	ms-olap3 	Microsoft OLAP
2382 	udp 	ms-olap3 	Microsoft OLAP
2383 	tcp 	ms-olap4 	Microsoft OLAP
2383 	udp 	ms-olap4 	Microsoft OLAP
2384 	tcp 	sd-request 	SD-REQUEST
2384 	udp 	sd-capacity 	SD-CAPACITY
2385 	tcp 	sd-data 	SD-DATA
2385 	udp 	sd-data 	SD-DATA
2386 	tcp 	virtualtape 	Virtual Tape
2386 	udp 	virtualtape 	Virtual Tape
2387 	tcp 	vsamredirector 	VSAM Redirector
2387 	udp 	vsamredirector 	VSAM Redirector
2388 	tcp 	mynahautostart 	MYNAH AutoStart
2388 	udp 	mynahautostart 	MYNAH AutoStart
2389 	tcp 	ovsessionmgr 	OpenView Session Mgr
2389 	udp 	ovsessionmgr 	OpenView Session Mgr
2390 	tcp 	rsmtp 	RSMTP
2390 	udp 	rsmtp 	RSMTP
2391 	tcp 	3com-net-mgmt 	3COM Net Management
2391 	udp 	3com-net-mgmt 	3COM Net Management
2392 	tcp 	tacticalauth 	Tactical Auth
2392 	udp 	tacticalauth 	Tactical Auth
2393 	tcp 	ms-olap1 	MS OLAP 1
2393 	udp 	ms-olap1 	MS OLAP 1
2394 	tcp 	ms-olap2 	MS OLAP 2
2394 	udp 	ms-olap2 	MS OLAP 2
2395 	tcp 	lan900-remote 	LAN900 Remote
IANA assigned this well-formed service name as a replacement for “lan900_remote”.
2395 	tcp 	lan900_remote 	LAN900 Remote
2395 	udp 	lan900-remote 	LAN900 Remote
IANA assigned this well-formed service name as a replacement for “lan900_remote”.
2395 	udp 	lan900_remote 	LAN900 Remote
2396 	tcp 	wusage 	Wusage
2396 	udp 	wusage 	Wusage
2397 	tcp 	ncl 	NCL
2397 	udp 	ncl 	NCL
2398 	tcp 	orbiter 	Orbiter
2398 	udp 	orbiter 	Orbiter
2399 	tcp 	fmpro-fdal 	FileMaker, Inc. – Data Access Layer
2399 	udp 	fmpro-fdal 	FileMaker, Inc. – Data Access Layer
2400 	tcp 	opequus-server 	OpEquus Server
2400 	udp 	opequus-server 	OpEquus Server
2401 	tcp 	cvspserver 	cvspserver
2401 	udp 	cvspserver 	cvspserver
2402 	tcp 	taskmaster2000 	TaskMaster 2000 Server
2402 	udp 	taskmaster2000 	TaskMaster 2000 Server
2403 	tcp 	taskmaster2000 	TaskMaster 2000 Web
2403 	udp 	taskmaster2000 	TaskMaster 2000 Web
2404 	tcp 	iec-104 	IEC 60870-5-104 process control over IP
2404 	udp 	iec-104 	IEC 60870-5-104 process control over IP
2405 	tcp 	trc-netpoll 	TRC Netpoll
2405 	udp 	trc-netpoll 	TRC Netpoll
2406 	tcp 	jediserver 	JediServer
2406 	udp 	jediserver 	JediServer
2407 	tcp 	orion 	Orion
2407 	udp 	orion 	Orion
2408 	tcp 	railgun-webaccl 	CloudFlare Railgun Web Acceleration Protocol
2408 	udp 		Reserved
2409 	tcp 	sns-protocol 	SNS Protocol
2409 	udp 	sns-protocol 	SNS Protocol
2410 	tcp 	vrts-registry 	VRTS Registry
2410 	udp 	vrts-registry 	VRTS Registry
2411 	tcp 	netwave-ap-mgmt 	Netwave AP Management
2411 	udp 	netwave-ap-mgmt 	Netwave AP Management
2412 	tcp 	cdn 	CDN
2412 	udp 	cdn 	CDN
2413 	tcp 	orion-rmi-reg 	orion-rmi-reg
2413 	udp 	orion-rmi-reg 	orion-rmi-reg
2414 	tcp 	beeyond 	Beeyond
2414 	udp 	beeyond 	Beeyond
2415 	tcp 	codima-rtp 	Codima Remote Transaction Protocol
2415 	udp 	codima-rtp 	Codima Remote Transaction Protocol
2416 	tcp 	rmtserver 	RMT Server
2416 	udp 	rmtserver 	RMT Server
2417 	tcp 	composit-server 	Composit Server
2417 	udp 	composit-server 	Composit Server
2418 	tcp 	cas 	cas
2418 	udp 	cas 	cas
2419 	tcp 	attachmate-s2s 	Attachmate S2S
2419 	udp 	attachmate-s2s 	Attachmate S2S
2420 	tcp 	dslremote-mgmt 	DSL Remote Management
2420 	udp 	dslremote-mgmt 	DSL Remote Management
2421 	tcp 	g-talk 	G-Talk
2421 	udp 	g-talk 	G-Talk
2422 	tcp 	crmsbits 	CRMSBITS
2422 	udp 	crmsbits 	CRMSBITS
2423 	tcp 	rnrp 	RNRP
2423 	udp 	rnrp 	RNRP
2424 	tcp 	kofax-svr 	KOFAX-SVR
2424 	udp 	kofax-svr 	KOFAX-SVR
2425 	tcp 	fjitsuappmgr 	Fujitsu App Manager
2425 	udp 	fjitsuappmgr 	Fujitsu App Manager
2426 	tcp 	vcmp 	VeloCloud MultiPath Protocol
2426 	udp 	vcmp 	VeloCloud MultiPath Protocol
2427 	tcp 	mgcp-gateway 	Media Gateway Control Protocol Gateway
2427 	udp 	mgcp-gateway 	Media Gateway Control Protocol Gateway
2428 	tcp 	ott 	One Way Trip Time
2428 	udp 	ott 	One Way Trip Time
2429 	tcp 	ft-role 	FT-ROLE
2429 	udp 	ft-role 	FT-ROLE
2430 	tcp 	venus 	venus
2430 	udp 	venus 	venus
2431 	tcp 	venus-se 	venus-se
2431 	udp 	venus-se 	venus-se
2432 	tcp 	codasrv 	codasrv
2432 	udp 	codasrv 	codasrv
2433 	tcp 	codasrv-se 	codasrv-se
2433 	udp 	codasrv-se 	codasrv-se
2434 	tcp 	pxc-epmap 	pxc-epmap
2434 	udp 	pxc-epmap 	pxc-epmap
2435 	tcp 	optilogic 	OptiLogic
2435 	udp 	optilogic 	OptiLogic
2436 	tcp 	topx 	TOP/X
2436 	udp 	topx 	TOP/X
2437 	tcp 	unicontrol 	UniControl
2437 	udp 	unicontrol 	UniControl
2438 	tcp 	msp 	MSP
2438 	udp 	msp 	MSP
2439 	tcp 	sybasedbsynch 	SybaseDBSynch
2439 	udp 	sybasedbsynch 	SybaseDBSynch
2440 	tcp 	spearway 	Spearway Lockers
2440 	udp 	spearway 	Spearway Lockers
2441 	tcp 	pvsw-inet 	Pervasive I*net Data Server
2441 	udp 	pvsw-inet 	Pervasive I*net Data Server
2442 	tcp 	netangel 	Netangel
2442 	udp 	netangel 	Netangel
2443 	tcp 	powerclientcsf 	PowerClient Central Storage Facility
2443 	udp 	powerclientcsf 	PowerClient Central Storage Facility
2444 	tcp 	btpp2sectrans 	BT PP2 Sectrans
2444 	udp 	btpp2sectrans 	BT PP2 Sectrans
2445 	tcp 	dtn1 	DTN1
2445 	udp 	dtn1 	DTN1
2446 	tcp 	bues-service 	bues_service
IANA assigned this well-formed service name as a replacement for “bues_service”.
2446 	tcp 	bues_service 	bues_service
2446 	udp 	bues-service 	bues_service
IANA assigned this well-formed service name as a replacement for “bues_service”.
2446 	udp 	bues_service 	bues_service
2447 	tcp 	ovwdb 	OpenView NNM daemon
2447 	udp 	ovwdb 	OpenView NNM daemon
2448 	tcp 	hpppssvr 	hpppsvr
2448 	udp 	hpppssvr 	hpppsvr
2449 	tcp 	ratl 	RATL
2449 	udp 	ratl 	RATL
2450 	tcp 	netadmin 	netadmin
2450 	udp 	netadmin 	netadmin
2451 	tcp 	netchat 	netchat
2451 	udp 	netchat 	netchat
2452 	tcp 	snifferclient 	SnifferClient
2452 	udp 	snifferclient 	SnifferClient
2453 	tcp 	madge-ltd 	madge ltd
2453 	udp 	madge-ltd 	madge ltd
2454 	tcp 	indx-dds 	IndX-DDS
2454 	udp 	indx-dds 	IndX-DDS
2455 	tcp 	wago-io-system 	WAGO-IO-SYSTEM
2455 	udp 	wago-io-system 	WAGO-IO-SYSTEM
2456 	tcp 	altav-remmgt 	altav-remmgt
2456 	udp 	altav-remmgt 	altav-remmgt
2457 	tcp 	rapido-ip 	Rapido_IP
2457 	udp 	rapido-ip 	Rapido_IP
2458 	tcp 	griffin 	griffin
2458 	udp 	griffin 	griffin
2459 	tcp 	community 	Community
2459 	udp 	community 	Community
2460 	tcp 	ms-theater 	ms-theater
2460 	udp 	ms-theater 	ms-theater
2461 	tcp 	qadmifoper 	qadmifoper
2461 	udp 	qadmifoper 	qadmifoper
2462 	tcp 	qadmifevent 	qadmifevent
2462 	udp 	qadmifevent 	qadmifevent
2463 	tcp 	lsi-raid-mgmt 	LSI RAID Management
2463 	udp 	lsi-raid-mgmt 	LSI RAID Management
2464 	tcp 	direcpc-si 	DirecPC SI
2464 	udp 	direcpc-si 	DirecPC SI
2465 	tcp 	lbm 	Load Balance Management
2465 	udp 	lbm 	Load Balance Management
2466 	tcp 	lbf 	Load Balance Forwarding
2466 	udp 	lbf 	Load Balance Forwarding
2467 	tcp 	high-criteria 	High Criteria
2467 	udp 	high-criteria 	High Criteria
2468 	tcp 	qip-msgd 	qip_msgd
2468 	udp 	qip-msgd 	qip_msgd
2469 	tcp 	mti-tcs-comm 	MTI-TCS-COMM
2469 	udp 	mti-tcs-comm 	MTI-TCS-COMM
2470 	tcp 	taskman-port 	taskman port
2470 	udp 	taskman-port 	taskman port
2471 	tcp 	seaodbc 	SeaODBC
2471 	udp 	seaodbc 	SeaODBC
2472 	tcp 	c3 	C3
2472 	udp 	c3 	C3
2473 	tcp 	aker-cdp 	Aker-cdp
2473 	udp 	aker-cdp 	Aker-cdp
2474 	tcp 	vitalanalysis 	Vital Analysis
2474 	udp 	vitalanalysis 	Vital Analysis
2475 	tcp 	ace-server 	ACE Server
2475 	udp 	ace-server 	ACE Server
2476 	tcp 	ace-svr-prop 	ACE Server Propagation
2476 	udp 	ace-svr-prop 	ACE Server Propagation
2477 	tcp 	ssm-cvs 	SecurSight Certificate Valifation Service
2477 	udp 	ssm-cvs 	SecurSight Certificate Valifation Service
2478 	tcp 	ssm-cssps 	SecurSight Authentication Server (SSL)
2478 	udp 	ssm-cssps 	SecurSight Authentication Server (SSL)
2479 	tcp 	ssm-els 	SecurSight Event Logging Server (SSL)
2479 	udp 	ssm-els 	SecurSight Event Logging Server (SSL)
2480 	tcp 	powerexchange 	Informatica PowerExchange Listener
2480 	udp 	powerexchange 	Informatica PowerExchange Listener
2481 	tcp 	giop 	Oracle GIOP
2481 	udp 	giop 	Oracle GIOP
2482 	tcp 	giop-ssl 	Oracle GIOP SSL
2482 	udp 	giop-ssl 	Oracle GIOP SSL
2483 	tcp 	ttc 	Oracle TTC
2483 	udp 	ttc 	Oracle TTC
2484 	tcp 	ttc-ssl 	Oracle TTC SSL
2484 	udp 	ttc-ssl 	Oracle TTC SSL
2485 	tcp 	netobjects1 	Net Objects1
2485 	udp 	netobjects1 	Net Objects1
2486 	tcp 	netobjects2 	Net Objects2
2486 	udp 	netobjects2 	Net Objects2
2487 	tcp 	pns 	Policy Notice Service
2487 	udp 	pns 	Policy Notice Service
2488 	tcp 	moy-corp 	Moy Corporation
2488 	udp 	moy-corp 	Moy Corporation
2489 	tcp 	tsilb 	TSILB
2489 	udp 	tsilb 	TSILB
2490 	tcp 	qip-qdhcp 	qip_qdhcp
2490 	udp 	qip-qdhcp 	qip_qdhcp
2491 	tcp 	conclave-cpp 	Conclave CPP
2491 	udp 	conclave-cpp 	Conclave CPP
2492 	tcp 	groove 	GROOVE
2492 	udp 	groove 	GROOVE
2493 	tcp 	talarian-mqs 	Talarian MQS
2493 	udp 	talarian-mqs 	Talarian MQS
2494 	tcp 	bmc-ar 	BMC AR
2494 	udp 	bmc-ar 	BMC AR
2495 	tcp 	fast-rem-serv 	Fast Remote Services
2495 	udp 	fast-rem-serv 	Fast Remote Services
2496 	tcp 	dirgis 	DIRGIS
2496 	udp 	dirgis 	DIRGIS
2497 	tcp 	quaddb 	Quad DB
2497 	udp 	quaddb 	Quad DB
2498 	tcp 	odn-castraq 	ODN-CasTraq
2498 	udp 	odn-castraq 	ODN-CasTraq
2499 	tcp 	unicontrol 	UniControl
2499 	udp 	unicontrol 	UniControl
2500 	tcp 	rtsserv 	Resource Tracking system server
2500 	udp 	rtsserv 	Resource Tracking system server
2501 	tcp 	rtsclient 	Resource Tracking system client
2501 	udp 	rtsclient 	Resource Tracking system client
2502 	tcp 	kentrox-prot 	Kentrox Protocol
2502 	udp 	kentrox-prot 	Kentrox Protocol
2503 	tcp 	nms-dpnss 	NMS-DPNSS
2503 	udp 	nms-dpnss 	NMS-DPNSS
2504 	tcp 	wlbs 	WLBS
2504 	udp 	wlbs 	WLBS
2505 	tcp 	ppcontrol 	PowerPlay Control
2505 	udp 	ppcontrol 	PowerPlay Control
2506 	tcp 	jbroker 	jbroker
2506 	udp 	jbroker 	jbroker
2507 	tcp 	spock 	spock
2507 	udp 	spock 	spock
2508 	tcp 	jdatastore 	JDataStore
2508 	udp 	jdatastore 	JDataStore
2509 	tcp 	fjmpss 	fjmpss
2509 	udp 	fjmpss 	fjmpss
2510 	tcp 	fjappmgrbulk 	fjappmgrbulk
2510 	udp 	fjappmgrbulk 	fjappmgrbulk
2511 	tcp 	metastorm 	Metastorm
2511 	udp 	metastorm 	Metastorm
2512 	tcp 	citrixima 	Citrix IMA
2512 	udp 	citrixima 	Citrix IMA
2513 	tcp 	citrixadmin 	Citrix ADMIN
2513 	udp 	citrixadmin 	Citrix ADMIN
2514 	tcp 	facsys-ntp 	Facsys NTP
2514 	udp 	facsys-ntp 	Facsys NTP
2515 	tcp 	facsys-router 	Facsys Router
2515 	udp 	facsys-router 	Facsys Router
2516 	tcp 	maincontrol 	Main Control
2516 	udp 	maincontrol 	Main Control
2517 	tcp 	call-sig-trans 	H.323 Annex E Call Control Signalling Transport
2517 	udp 	call-sig-trans 	H.323 Annex E Call Control Signalling Transport
2518 	tcp 	willy 	Willy
2518 	udp 	willy 	Willy
2519 	tcp 	globmsgsvc 	globmsgsvc
2519 	udp 	globmsgsvc 	globmsgsvc
2520 	tcp 	pvsw 	Pervasive Listener
2520 	udp 	pvsw 	Pervasive Listener
2521 	tcp 	adaptecmgr 	Adaptec Manager
2521 	udp 	adaptecmgr 	Adaptec Manager
2522 	tcp 	windb 	WinDb
2522 	udp 	windb 	WinDb
2523 	tcp 	qke-llc-v3 	Qke LLC V.3
2523 	udp 	qke-llc-v3 	Qke LLC V.3
2524 	tcp 	optiwave-lm 	Optiwave License Management
2524 	udp 	optiwave-lm 	Optiwave License Management
2525 	tcp 	ms-v-worlds 	MS V-Worlds
2525 	udp 	ms-v-worlds 	MS V-Worlds
2526 	tcp 	ema-sent-lm 	EMA License Manager
2526 	udp 	ema-sent-lm 	EMA License Manager
2527 	tcp 	iqserver 	IQ Server
2527 	udp 	iqserver 	IQ Server
2528 	tcp 	ncr-ccl 	NCR CCL
IANA assigned this well-formed service name as a replacement for “ncr_ccl”.
2528 	tcp 	ncr_ccl 	NCR CCL
2528 	udp 	ncr-ccl 	NCR CCL
IANA assigned this well-formed service name as a replacement for “ncr_ccl”.
2528 	udp 	ncr_ccl 	NCR CCL
2529 	tcp 	utsftp 	UTS FTP
2529 	udp 	utsftp 	UTS FTP
2530 	tcp 	vrcommerce 	VR Commerce
2530 	udp 	vrcommerce 	VR Commerce
2531 	tcp 	ito-e-gui 	ITO-E GUI
2531 	udp 	ito-e-gui 	ITO-E GUI
2532 	tcp 	ovtopmd 	OVTOPMD
2532 	udp 	ovtopmd 	OVTOPMD
2533 	tcp 	snifferserver 	SnifferServer
2533 	udp 	snifferserver 	SnifferServer
2534 	tcp 	combox-web-acc 	Combox Web Access
2534 	udp 	combox-web-acc 	Combox Web Access
2535 	tcp 	madcap 	MADCAP
2535 	udp 	madcap 	MADCAP
2536 	tcp 	btpp2audctr1 	btpp2audctr1
2536 	udp 	btpp2audctr1 	btpp2audctr1
2537 	tcp 	upgrade 	Upgrade Protocol
2537 	udp 	upgrade 	Upgrade Protocol
2538 	tcp 	vnwk-prapi 	vnwk-prapi
2538 	udp 	vnwk-prapi 	vnwk-prapi
2539 	tcp 	vsiadmin 	VSI Admin
2539 	udp 	vsiadmin 	VSI Admin
2540 	tcp 	lonworks 	LonWorks
2540 	udp 	lonworks 	LonWorks
2541 	tcp 	lonworks2 	LonWorks2
2541 	udp 	lonworks2 	LonWorks2
2542 	tcp 	udrawgraph 	uDraw(Graph)
2542 	udp 	udrawgraph 	uDraw(Graph)
2543 	tcp 	reftek 	REFTEK
2543 	udp 	reftek 	REFTEK
2544 	tcp 	novell-zen 	Management Daemon Refresh
2544 	udp 	novell-zen 	Management Daemon Refresh
2545 	tcp 	sis-emt 	sis-emt
2545 	udp 	sis-emt 	sis-emt
2546 	tcp 	vytalvaultbrtp 	vytalvaultbrtp
2546 	udp 	vytalvaultbrtp 	vytalvaultbrtp
2547 	tcp 	vytalvaultvsmp 	vytalvaultvsmp
2547 	udp 	vytalvaultvsmp 	vytalvaultvsmp
2548 	tcp 	vytalvaultpipe 	vytalvaultpipe
2548 	udp 	vytalvaultpipe 	vytalvaultpipe
2549 	tcp 	ipass 	IPASS
2549 	udp 	ipass 	IPASS
2550 	tcp 	ads 	ADS
2550 	udp 	ads 	ADS
2551 	tcp 	isg-uda-server 	ISG UDA Server
2551 	udp 	isg-uda-server 	ISG UDA Server
2552 	tcp 	call-logging 	Call Logging
2552 	udp 	call-logging 	Call Logging
2553 	tcp 	efidiningport 	efidiningport
2553 	udp 	efidiningport 	efidiningport
2554 	tcp 	vcnet-link-v10 	VCnet-Link v10
2554 	udp 	vcnet-link-v10 	VCnet-Link v10
2555 	tcp 	compaq-wcp 	Compaq WCP
2555 	udp 	compaq-wcp 	Compaq WCP
2556 	tcp 	nicetec-nmsvc 	nicetec-nmsvc
2556 	udp 	nicetec-nmsvc 	nicetec-nmsvc
2557 	tcp 	nicetec-mgmt 	nicetec-mgmt
2557 	udp 	nicetec-mgmt 	nicetec-mgmt
2558 	tcp 	pclemultimedia 	PCLE Multi Media
2558 	udp 	pclemultimedia 	PCLE Multi Media
2559 	tcp 	lstp 	LSTP
2559 	udp 	lstp 	LSTP
2560 	tcp 	labrat 	labrat
2560 	udp 	labrat 	labrat
2561 	tcp 	mosaixcc 	MosaixCC
2561 	udp 	mosaixcc 	MosaixCC
2562 	tcp 	delibo 	Delibo
2562 	udp 	delibo 	Delibo
2563 	tcp 	cti-redwood 	CTI Redwood
2563 	udp 	cti-redwood 	CTI Redwood
2564 	tcp 	hp-3000-telnet 	HP 3000 NS/VT block mode telnet
2564 	udp 	hp-3000-telnet 	HP 3000 NS/VT block mode telnet
2565 	tcp 	coord-svr 	Coordinator Server
2565 	udp 	coord-svr 	Coordinator Server
2566 	tcp 	pcs-pcw 	pcs-pcw
2566 	udp 	pcs-pcw 	pcs-pcw
2567 	tcp 	clp 	Cisco Line Protocol
2567 	udp 	clp 	Cisco Line Protocol
2568 	tcp 	spamtrap 	SPAM TRAP
2568 	udp 	spamtrap 	SPAM TRAP
2569 	tcp 	sonuscallsig 	Sonus Call Signal
2569 	udp 	sonuscallsig 	Sonus Call Signal
2570 	tcp 	hs-port 	HS Port
2570 	udp 	hs-port 	HS Port
2571 	tcp 	cecsvc 	CECSVC
2571 	udp 	cecsvc 	CECSVC
2572 	tcp 	ibp 	IBP
2572 	udp 	ibp 	IBP
2573 	tcp 	trustestablish 	Trust Establish
2573 	udp 	trustestablish 	Trust Establish
2574 	tcp 	blockade-bpsp 	Blockade BPSP
2574 	udp 	blockade-bpsp 	Blockade BPSP
2575 	tcp 	hl7 	HL7
2575 	udp 	hl7 	HL7
2576 	tcp 	tclprodebugger 	TCL Pro Debugger
2576 	udp 	tclprodebugger 	TCL Pro Debugger
2577 	tcp 	scipticslsrvr 	Scriptics Lsrvr
2577 	udp 	scipticslsrvr 	Scriptics Lsrvr
2578 	tcp 	rvs-isdn-dcp 	RVS ISDN DCP
2578 	udp 	rvs-isdn-dcp 	RVS ISDN DCP
2579 	tcp 	mpfoncl 	mpfoncl
2579 	udp 	mpfoncl 	mpfoncl
2580 	tcp 	tributary 	Tributary
2580 	udp 	tributary 	Tributary
2581 	tcp 	argis-te 	ARGIS TE
2581 	udp 	argis-te 	ARGIS TE
2582 	tcp 	argis-ds 	ARGIS DS
2582 	udp 	argis-ds 	ARGIS DS
2583 	tcp 	mon 	MON
2583 	udp 	mon 	MON
2584 	tcp 	cyaserv 	cyaserv
2584 	udp 	cyaserv 	cyaserv
2585 	tcp 	netx-server 	NETX Server
2585 	udp 	netx-server 	NETX Server
2586 	tcp 	netx-agent 	NETX Agent
2586 	udp 	netx-agent 	NETX Agent
2587 	tcp 	masc 	MASC
2587 	udp 	masc 	MASC
2588 	tcp 	privilege 	Privilege
2588 	udp 	privilege 	Privilege
2589 	tcp 	quartus-tcl 	quartus tcl
2589 	udp 	quartus-tcl 	quartus tcl
2590 	tcp 	idotdist 	idotdist
2590 	udp 	idotdist 	idotdist
2591 	tcp 	maytagshuffle 	Maytag Shuffle
2591 	udp 	maytagshuffle 	Maytag Shuffle
2592 	tcp 	netrek 	netrek
2592 	udp 	netrek 	netrek
2593 	tcp 	mns-mail 	MNS Mail Notice Service
2593 	udp 	mns-mail 	MNS Mail Notice Service
2594 	tcp 	dts 	Data Base Server
2594 	udp 	dts 	Data Base Server
2595 	tcp 	worldfusion1 	World Fusion 1
2595 	udp 	worldfusion1 	World Fusion 1
2596 	tcp 	worldfusion2 	World Fusion 2
2596 	udp 	worldfusion2 	World Fusion 2
2597 	tcp 	homesteadglory 	Homestead Glory
2597 	udp 	homesteadglory 	Homestead Glory
2598 	tcp 	citriximaclient 	Citrix MA Client
2598 	udp 	citriximaclient 	Citrix MA Client
2599 	tcp 	snapd 	Snap Discovery
2599 	udp 	snapd 	Snap Discovery
2600 	tcp 	hpstgmgr 	HPSTGMGR
2600 	udp 	hpstgmgr 	HPSTGMGR
2601 	tcp 	discp-client 	discp client
2601 	udp 	discp-client 	discp client
2602 	tcp 	discp-server 	discp server
2602 	udp 	discp-server 	discp server
2603 	tcp 	servicemeter 	Service Meter
2603 	udp 	servicemeter 	Service Meter
2604 	tcp 	nsc-ccs 	NSC CCS
2604 	udp 	nsc-ccs 	NSC CCS
2605 	tcp 	nsc-posa 	NSC POSA
2605 	udp 	nsc-posa 	NSC POSA
2606 	tcp 	netmon 	Dell Netmon
2606 	udp 	netmon 	Dell Netmon
2607 	tcp 	connection 	Dell Connection
2607 	udp 	connection 	Dell Connection
2608 	tcp 	wag-service 	Wag Service
2608 	udp 	wag-service 	Wag Service
2609 	tcp 	system-monitor 	System Monitor
2609 	udp 	system-monitor 	System Monitor
2610 	tcp 	versa-tek 	VersaTek
2610 	udp 	versa-tek 	VersaTek
2611 	tcp 	lionhead 	LIONHEAD
2611 	udp 	lionhead 	LIONHEAD
2612 	tcp 	qpasa-agent 	Qpasa Agent
2612 	udp 	qpasa-agent 	Qpasa Agent
2613 	tcp 	smntubootstrap 	SMNTUBootstrap
2613 	udp 	smntubootstrap 	SMNTUBootstrap
2614 	tcp 	neveroffline 	Never Offline
2614 	udp 	neveroffline 	Never Offline
2615 	tcp 	firepower 	firepower
2615 	udp 	firepower 	firepower
2616 	tcp 	appswitch-emp 	appswitch-emp
2616 	udp 	appswitch-emp 	appswitch-emp
2617 	tcp 	cmadmin 	Clinical Context Managers
2617 	udp 	cmadmin 	Clinical Context Managers
2618 	tcp 	priority-e-com 	Priority E-Com
2618 	udp 	priority-e-com 	Priority E-Com
2619 	tcp 	bruce 	bruce
2619 	udp 	bruce 	bruce
2620 	tcp 	lpsrecommender 	LPSRecommender
2620 	udp 	lpsrecommender 	LPSRecommender
2621 	tcp 	miles-apart 	Miles Apart Jukebox Server
2621 	udp 	miles-apart 	Miles Apart Jukebox Server
2622 	tcp 	metricadbc 	MetricaDBC
2622 	udp 	metricadbc 	MetricaDBC
2623 	tcp 	lmdp 	LMDP
2623 	udp 	lmdp 	LMDP
2624 	tcp 	aria 	Aria
2624 	udp 	aria 	Aria
2625 	tcp 	blwnkl-port 	Blwnkl Port
2625 	udp 	blwnkl-port 	Blwnkl Port
2626 	tcp 	gbjd816 	gbjd816
2626 	udp 	gbjd816 	gbjd816
2627 	tcp 	moshebeeri 	Moshe Beeri
2627 	udp 	moshebeeri 	Moshe Beeri
2628 	tcp 	dict 	DICT
2628 	udp 	dict 	DICT
2629 	tcp 	sitaraserver 	Sitara Server
2629 	udp 	sitaraserver 	Sitara Server
2630 	tcp 	sitaramgmt 	Sitara Management
2630 	udp 	sitaramgmt 	Sitara Management
2631 	tcp 	sitaradir 	Sitara Dir
2631 	udp 	sitaradir 	Sitara Dir
2632 	tcp 	irdg-post 	IRdg Post
2632 	udp 	irdg-post 	IRdg Post
2633 	tcp 	interintelli 	InterIntelli
2633 	udp 	interintelli 	InterIntelli
2634 	tcp 	pk-electronics 	PK Electronics
2634 	udp 	pk-electronics 	PK Electronics
2635 	tcp 	backburner 	Back Burner
2635 	udp 	backburner 	Back Burner
2636 	tcp 	solve 	Solve
2636 	udp 	solve 	Solve
2637 	tcp 	imdocsvc 	Import Document Service
2637 	udp 	imdocsvc 	Import Document Service
2638 	tcp 	sybaseanywhere 	Sybase Anywhere
2638 	udp 	sybaseanywhere 	Sybase Anywhere
2639 	tcp 	aminet 	AMInet
2639 	udp 	aminet 	AMInet
2640 	tcp 	ami-control 	Alcorn McBride Inc protocol used for device contr
2640 	udp 	ami-control 	Alcorn McBride Inc protocol used for device contr
2641 	tcp 	hdl-srv 	HDL Server
2641 	udp 	hdl-srv 	HDL Server
2642 	tcp 	tragic 	Tragic
2642 	udp 	tragic 	Tragic
2643 	tcp 	gte-samp 	GTE-SAMP
2643 	udp 	gte-samp 	GTE-SAMP
2644 	tcp 	travsoft-ipx-t 	Travsoft IPX Tunnel
2644 	udp 	travsoft-ipx-t 	Travsoft IPX Tunnel
2645 	tcp 	novell-ipx-cmd 	Novell IPX CMD
2645 	udp 	novell-ipx-cmd 	Novell IPX CMD
2646 	tcp 	and-lm 	AND License Manager
2646 	udp 	and-lm 	AND License Manager
2647 	tcp 	syncserver 	SyncServer
2647 	udp 	syncserver 	SyncServer
2648 	tcp 	upsnotifyprot 	Upsnotifyprot
2648 	udp 	upsnotifyprot 	Upsnotifyprot
2649 	tcp 	vpsipport 	VPSIPPORT
2649 	udp 	vpsipport 	VPSIPPORT
2650 	tcp 	eristwoguns 	eristwoguns
2650 	udp 	eristwoguns 	eristwoguns
2651 	tcp 	ebinsite 	EBInSite
2651 	udp 	ebinsite 	EBInSite
2652 	tcp 	interpathpanel 	InterPathPanel
2652 	udp 	interpathpanel 	InterPathPanel
2653 	tcp 	sonus 	Sonus
2653 	udp 	sonus 	Sonus
2654 	tcp 	corel-vncadmin 	Corel VNC Admin
IANA assigned this well-formed service name as a replacement for “corel_vncadmin”.
2654 	tcp 	corel_vncadmin 	Corel VNC Admin
2654 	udp 	corel-vncadmin 	Corel VNC Admin
IANA assigned this well-formed service name as a replacement for “corel_vncadmin”.
2654 	udp 	corel_vncadmin 	Corel VNC Admin
2655 	tcp 	unglue 	UNIX Nt Glue
2655 	udp 	unglue 	UNIX Nt Glue
2656 	tcp 	kana 	Kana
2656 	udp 	kana 	Kana
2657 	tcp 	sns-dispatcher 	SNS Dispatcher
2657 	udp 	sns-dispatcher 	SNS Dispatcher
2658 	tcp 	sns-admin 	SNS Admin
2658 	udp 	sns-admin 	SNS Admin
2659 	tcp 	sns-query 	SNS Query
2659 	udp 	sns-query 	SNS Query
2660 	tcp 	gcmonitor 	GC Monitor
2660 	udp 	gcmonitor 	GC Monitor
2661 	tcp 	olhost 	OLHOST
2661 	udp 	olhost 	OLHOST
2662 	tcp 	bintec-capi 	BinTec-CAPI
2662 	udp 	bintec-capi 	BinTec-CAPI
2663 	tcp 	bintec-tapi 	BinTec-TAPI
2663 	udp 	bintec-tapi 	BinTec-TAPI
2664 	tcp 	patrol-mq-gm 	Patrol for MQ GM
2664 	udp 	patrol-mq-gm 	Patrol for MQ GM
2665 	tcp 	patrol-mq-nm 	Patrol for MQ NM
2665 	udp 	patrol-mq-nm 	Patrol for MQ NM
2666 	tcp 	extensis 	extensis
2666 	udp 	extensis 	extensis
2667 	tcp 	alarm-clock-s 	Alarm Clock Server
2667 	udp 	alarm-clock-s 	Alarm Clock Server
2668 	tcp 	alarm-clock-c 	Alarm Clock Client
2668 	udp 	alarm-clock-c 	Alarm Clock Client
2669 	tcp 	toad 	TOAD
2669 	udp 	toad 	TOAD
2670 	tcp 	tve-announce 	TVE Announce
2670 	udp 	tve-announce 	TVE Announce
2671 	tcp 	newlixreg 	newlixreg
2671 	udp 	newlixreg 	newlixreg
2672 	tcp 	nhserver 	nhserver
2672 	udp 	nhserver 	nhserver
2673 	tcp 	firstcall42 	First Call 42
2673 	udp 	firstcall42 	First Call 42
2674 	tcp 	ewnn 	ewnn
2674 	udp 	ewnn 	ewnn
2675 	tcp 	ttc-etap 	TTC ETAP
2675 	udp 	ttc-etap 	TTC ETAP
2676 	tcp 	simslink 	SIMSLink
2676 	udp 	simslink 	SIMSLink
2677 	tcp 	gadgetgate1way 	Gadget Gate 1 Way
2677 	udp 	gadgetgate1way 	Gadget Gate 1 Way
2678 	tcp 	gadgetgate2way 	Gadget Gate 2 Way
2678 	udp 	gadgetgate2way 	Gadget Gate 2 Way
2679 	tcp 	syncserverssl 	Sync Server SSL
2679 	udp 	syncserverssl 	Sync Server SSL
2680 	tcp 	pxc-sapxom 	pxc-sapxom
2680 	udp 	pxc-sapxom 	pxc-sapxom
2681 	tcp 	mpnjsomb 	mpnjsomb
2681 	udp 	mpnjsomb 	mpnjsomb
2682 			Removed
2683 	tcp 	ncdloadbalance 	NCDLoadBalance
2683 	udp 	ncdloadbalance 	NCDLoadBalance
2684 	tcp 	mpnjsosv 	mpnjsosv
2684 	udp 	mpnjsosv 	mpnjsosv
2685 	tcp 	mpnjsocl 	mpnjsocl
2685 	udp 	mpnjsocl 	mpnjsocl
2686 	tcp 	mpnjsomg 	mpnjsomg
2686 	udp 	mpnjsomg 	mpnjsomg
2687 	tcp 	pq-lic-mgmt 	pq-lic-mgmt
2687 	udp 	pq-lic-mgmt 	pq-lic-mgmt
2688 	tcp 	md-cg-http 	md-cf-http
2688 	udp 	md-cg-http 	md-cf-http
2689 	tcp 	fastlynx 	FastLynx
2689 	udp 	fastlynx 	FastLynx
2690 	tcp 	hp-nnm-data 	HP NNM Embedded Database
2690 	udp 	hp-nnm-data 	HP NNM Embedded Database
2691 	tcp 	itinternet 	ITInternet ISM Server
2691 	udp 	itinternet 	ITInternet ISM Server
2692 	tcp 	admins-lms 	Admins LMS
2692 	udp 	admins-lms 	Admins LMS
2693 	tcp 		Unassigned
2693 	udp 		Unassigned
2694 	tcp 	pwrsevent 	pwrsevent
2694 	udp 	pwrsevent 	pwrsevent
2695 	tcp 	vspread 	VSPREAD
2695 	udp 	vspread 	VSPREAD
2696 	tcp 	unifyadmin 	Unify Admin
2696 	udp 	unifyadmin 	Unify Admin
2697 	tcp 	oce-snmp-trap 	Oce SNMP Trap Port
2697 	udp 	oce-snmp-trap 	Oce SNMP Trap Port
2698 	tcp 	mck-ivpip 	MCK-IVPIP
2698 	udp 	mck-ivpip 	MCK-IVPIP
2699 	tcp 	csoft-plusclnt 	Csoft Plus Client
2699 	udp 	csoft-plusclnt 	Csoft Plus Client
2700 	tcp 	tqdata 	tqdata
2700 	udp 	tqdata 	tqdata
2701 	tcp 	sms-rcinfo 	SMS RCINFO
2701 	udp 	sms-rcinfo 	SMS RCINFO
2702 	tcp 	sms-xfer 	SMS XFER
2702 	udp 	sms-xfer 	SMS XFER
2703 	tcp 	sms-chat 	SMS CHAT
2703 	udp 	sms-chat 	SMS CHAT
2704 	tcp 	sms-remctrl 	SMS REMCTRL
2704 	udp 	sms-remctrl 	SMS REMCTRL
2705 	tcp 	sds-admin 	SDS Admin
2705 	udp 	sds-admin 	SDS Admin
2706 	tcp 	ncdmirroring 	NCD Mirroring
2706 	udp 	ncdmirroring 	NCD Mirroring
2707 	tcp 	emcsymapiport 	EMCSYMAPIPORT
2707 	udp 	emcsymapiport 	EMCSYMAPIPORT
2708 	tcp 	banyan-net 	Banyan-Net
2708 	udp 	banyan-net 	Banyan-Net
2709 	tcp 	supermon 	Supermon
2709 	udp 	supermon 	Supermon
2710 	tcp 	sso-service 	SSO Service
2710 	udp 	sso-service 	SSO Service
2711 	tcp 	sso-control 	SSO Control
2711 	udp 	sso-control 	SSO Control
2712 	tcp 	aocp 	Axapta Object Communication Protocol
2712 	udp 	aocp 	Axapta Object Communication Protocol
2713 	tcp 	raventbs 	Raven Trinity Broker Service
2713 	udp 	raventbs 	Raven Trinity Broker Service
2714 	tcp 	raventdm 	Raven Trinity Data Mover
2714 	udp 	raventdm 	Raven Trinity Data Mover
2715 	tcp 	hpstgmgr2 	HPSTGMGR2
2715 	udp 	hpstgmgr2 	HPSTGMGR2
2716 	tcp 	inova-ip-disco 	Inova IP Disco
2716 	udp 	inova-ip-disco 	Inova IP Disco
2717 	tcp 	pn-requester 	PN REQUESTER
2717 	udp 	pn-requester 	PN REQUESTER
2718 	tcp 	pn-requester2 	PN REQUESTER 2
2718 	udp 	pn-requester2 	PN REQUESTER 2
2719 	tcp 	scan-change 	Scan & Change
2719 	udp 	scan-change 	Scan & Change
2720 	tcp 	wkars 	wkars
2720 	udp 	wkars 	wkars
2721 	tcp 	smart-diagnose 	Smart Diagnose
2721 	udp 	smart-diagnose 	Smart Diagnose
2722 	tcp 	proactivesrvr 	Proactive Server
2722 	udp 	proactivesrvr 	Proactive Server
2723 	tcp 	watchdog-nt 	WatchDog NT Protocol
2723 	udp 	watchdog-nt 	WatchDog NT Protocol
2724 	tcp 	qotps 	qotps
2724 	udp 	qotps 	qotps
2725 	tcp 	msolap-ptp2 	MSOLAP PTP2
2725 	udp 	msolap-ptp2 	MSOLAP PTP2
2726 	tcp 	tams 	TAMS
2726 	udp 	tams 	TAMS
2727 	tcp 	mgcp-callagent 	Media Gateway Control Protocol Call Agent
2727 	udp 	mgcp-callagent 	Media Gateway Control Protocol Call Agent
2728 	tcp 	sqdr 	SQDR
2728 	udp 	sqdr 	SQDR
2729 	tcp 	tcim-control 	TCIM Control
2729 	udp 	tcim-control 	TCIM Control
2730 	tcp 	nec-raidplus 	NEC RaidPlus
2730 	udp 	nec-raidplus 	NEC RaidPlus
2731 	tcp 	fyre-messanger 	Fyre Messanger
2731 	udp 	fyre-messanger 	Fyre Messagner
2732 	tcp 	g5m 	G5M
2732 	udp 	g5m 	G5M
2733 	tcp 	signet-ctf 	Signet CTF
2733 	udp 	signet-ctf 	Signet CTF
2734 	tcp 	ccs-software 	CCS Software
2734 	udp 	ccs-software 	CCS Software
2735 	tcp 	netiq-mc 	NetIQ Monitor Console
2735 	udp 	netiq-mc 	NetIQ Monitor Console
2736 	tcp 	radwiz-nms-srv 	RADWIZ NMS SRV
2736 	udp 	radwiz-nms-srv 	RADWIZ NMS SRV
2737 	tcp 	srp-feedback 	SRP Feedback
2737 	udp 	srp-feedback 	SRP Feedback
2738 	tcp 	ndl-tcp-ois-gw 	NDL TCP-OSI Gateway
2738 	udp 	ndl-tcp-ois-gw 	NDL TCP-OSI Gateway
2739 	tcp 	tn-timing 	TN Timing
2739 	udp 	tn-timing 	TN Timing
2740 	tcp 	alarm 	Alarm
2740 	udp 	alarm 	Alarm
2741 	tcp 	tsb 	TSB
2741 	udp 	tsb 	TSB
2742 	tcp 	tsb2 	TSB2
2742 	udp 	tsb2 	TSB2
2743 	tcp 	murx 	murx
2743 	udp 	murx 	murx
2744 	tcp 	honyaku 	honyaku
2744 	udp 	honyaku 	honyaku
2745 	tcp 	urbisnet 	URBISNET
2745 	udp 	urbisnet 	URBISNET
2746 	tcp 	cpudpencap 	CPUDPENCAP
2746 	udp 	cpudpencap 	CPUDPENCAP
2747 	tcp 	fjippol-swrly 	
2747 	udp 	fjippol-swrly 	
2748 	tcp 	fjippol-polsvr 	
2748 	udp 	fjippol-polsvr 	
2749 	tcp 	fjippol-cnsl 	
2749 	udp 	fjippol-cnsl 	
2750 	tcp 	fjippol-port1 	
2750 	udp 	fjippol-port1 	
2751 	tcp 	fjippol-port2 	
2751 	udp 	fjippol-port2 	
2752 	tcp 	rsisysaccess 	RSISYS ACCESS
2752 	udp 	rsisysaccess 	RSISYS ACCESS
2753 	tcp 	de-spot 	de-spot
2753 	udp 	de-spot 	de-spot
2754 	tcp 	apollo-cc 	APOLLO CC
2754 	udp 	apollo-cc 	APOLLO CC
2755 	tcp 	expresspay 	Express Pay
2755 	udp 	expresspay 	Express Pay
2756 	tcp 	simplement-tie 	simplement-tie
2756 	udp 	simplement-tie 	simplement-tie
2757 	tcp 	cnrp 	CNRP
2757 	udp 	cnrp 	CNRP
2758 	tcp 	apollo-status 	APOLLO Status
2758 	udp 	apollo-status 	APOLLO Status
2759 	tcp 	apollo-gms 	APOLLO GMS
2759 	udp 	apollo-gms 	APOLLO GMS
2760 	tcp 	sabams 	Saba MS
2760 	udp 	sabams 	Saba MS
2761 	tcp 	dicom-iscl 	DICOM ISCL
2761 	udp 	dicom-iscl 	DICOM ISCL
2762 	tcp 	dicom-tls 	DICOM TLS
2762 	udp 	dicom-tls 	DICOM TLS
2763 	tcp 	desktop-dna 	Desktop DNA
2763 	udp 	desktop-dna 	Desktop DNA
2764 	tcp 	data-insurance 	Data Insurance
2764 	udp 	data-insurance 	Data Insurance
2765 	tcp 	qip-audup 	qip-audup
2765 	udp 	qip-audup 	qip-audup
2766 	tcp 	compaq-scp 	Compaq SCP
2766 	udp 	compaq-scp 	Compaq SCP
2767 	tcp 	uadtc 	UADTC
2767 	udp 	uadtc 	UADTC
2768 	tcp 	uacs 	UACS
2768 	udp 	uacs 	UACS
2769 	tcp 	exce 	eXcE
2769 	udp 	exce 	eXcE
2770 	tcp 	veronica 	Veronica
2770 	udp 	veronica 	Veronica
2771 	tcp 	vergencecm 	Vergence CM
2771 	udp 	vergencecm 	Vergence CM
2772 	tcp 	auris 	auris
2772 	udp 	auris 	auris
2773 	tcp 	rbakcup1 	RBackup Remote Backup
2773 	udp 	rbakcup1 	RBackup Remote Backup
2774 	tcp 	rbakcup2 	RBackup Remote Backup
2774 	udp 	rbakcup2 	RBackup Remote Backup
2775 	tcp 	smpp 	SMPP
2775 	udp 	smpp 	SMPP
2776 	tcp 	ridgeway1 	Ridgeway Systems & Software
2776 	udp 	ridgeway1 	Ridgeway Systems & Software
2777 	tcp 	ridgeway2 	Ridgeway Systems & Software
2777 	udp 	ridgeway2 	Ridgeway Systems & Software
2778 	tcp 	gwen-sonya 	Gwen-Sonya
2778 	udp 	gwen-sonya 	Gwen-Sonya
2779 	tcp 	lbc-sync 	LBC Sync
2779 	udp 	lbc-sync 	LBC Sync
2780 	tcp 	lbc-control 	LBC Control
2780 	udp 	lbc-control 	LBC Control
2781 	tcp 	whosells 	whosells
2781 	udp 	whosells 	whosells
2782 	tcp 	everydayrc 	everydayrc
2782 	udp 	everydayrc 	everydayrc
2783 	tcp 	aises 	AISES
2783 	udp 	aises 	AISES
2784 	tcp 	www-dev 	world wide web – development
2784 	udp 	www-dev 	world wide web – development
2785 	tcp 	aic-np 	aic-np
2785 	udp 	aic-np 	aic-np
2786 	tcp 	aic-oncrpc 	aic-oncrpc – Destiny MCD database
2786 	udp 	aic-oncrpc 	aic-oncrpc – Destiny MCD database
2787 	tcp 	piccolo 	piccolo – Cornerstone Software
2787 	udp 	piccolo 	piccolo – Cornerstone Software
2788 	tcp 	fryeserv 	NetWare Loadable Module – Seagate Software
2788 	udp 	fryeserv 	NetWare Loadable Module – Seagate Software
2789 	tcp 	media-agent 	Media Agent
2789 	udp 	media-agent 	Media Agent
2790 	tcp 	plgproxy 	PLG Proxy
2790 	udp 	plgproxy 	PLG Proxy
2791 	tcp 	mtport-regist 	MT Port Registrator
2791 	udp 	mtport-regist 	MT Port Registrator
2792 	tcp 	f5-globalsite 	f5-globalsite
2792 	udp 	f5-globalsite 	f5-globalsite
2793 	tcp 	initlsmsad 	initlsmsad
2793 	udp 	initlsmsad 	initlsmsad
2794 			Unassigned
2795 	tcp 	livestats 	LiveStats
2795 	udp 	livestats 	LiveStats
2796 	tcp 	ac-tech 	ac-tech
2796 	udp 	ac-tech 	ac-tech
2797 	tcp 	esp-encap 	esp-encap
2797 	udp 	esp-encap 	esp-encap
2798 	tcp 	tmesis-upshot 	TMESIS-UPShot
2798 	udp 	tmesis-upshot 	TMESIS-UPShot
2799 	tcp 	icon-discover 	ICON Discover
2799 	udp 	icon-discover 	ICON Discover
2800 	tcp 	acc-raid 	ACC RAID
2800 	udp 	acc-raid 	ACC RAID
2801 	tcp 	igcp 	IGCP
2801 	udp 	igcp 	IGCP
2802 	tcp 	veritas-tcp1 	Veritas TCP1
2802 	udp 	veritas-udp1 	Veritas UDP1
2803 	tcp 	btprjctrl 	btprjctrl
2803 	udp 	btprjctrl 	btprjctrl
2804 	tcp 	dvr-esm 	March Networks DVR and Service Manager
2804 	udp 	dvr-esm 	March Networks DVR and Service Manager
2805 	tcp 	wta-wsp-s 	WTA WSP-S
2805 	udp 	wta-wsp-s 	WTA WSP-S
2806 	tcp 	cspuni 	cspuni
2806 	udp 	cspuni 	cspuni
2807 	tcp 	cspmulti 	cspmulti
2807 	udp 	cspmulti 	cspmulti
2808 	tcp 	j-lan-p 	J-LAN-P
2808 	udp 	j-lan-p 	J-LAN-P
2809 	tcp 	corbaloc 	CORBA LOC
2809 	udp 	corbaloc 	CORBA LOC
2810 	tcp 	netsteward 	Active Net Steward
2810 	udp 	netsteward 	Active Net Steward
2811 	tcp 	gsiftp 	GSI FTP
2811 	udp 	gsiftp 	GSI FTP
2812 	tcp 	atmtcp 	atmtcp
2812 	udp 	atmtcp 	atmtcp
2813 	tcp 	llm-pass 	llm-pass
2813 	udp 	llm-pass 	llm-pass
2814 	tcp 	llm-csv 	llm-csv
2814 	udp 	llm-csv 	llm-csv
2815 	tcp 	lbc-measure 	LBC Measurement
2815 	udp 	lbc-measure 	LBC Measurement
2816 	tcp 	lbc-watchdog 	LBC Watchdog
2816 	udp 	lbc-watchdog 	LBC Watchdog
2817 	tcp 	nmsigport 	NMSig Port
2817 	udp 	nmsigport 	NMSig Port
2818 	tcp 	rmlnk 	rmlnk
2818 	udp 	rmlnk 	rmlnk
2819 	tcp 	fc-faultnotify 	FC Fault Notification
2819 	udp 	fc-faultnotify 	FC Fault Notification
2820 	tcp 	univision 	UniVision
2820 	udp 	univision 	UniVision
2821 	tcp 	vrts-at-port 	VERITAS Authentication Service
2821 	udp 	vrts-at-port 	VERITAS Authentication Service
2822 	tcp 	ka0wuc 	ka0wuc
2822 	udp 	ka0wuc 	ka0wuc
2823 	tcp 	cqg-netlan 	CQG Net/LAN
2823 	udp 	cqg-netlan 	CQG Net/LAN
2824 	tcp 	cqg-netlan-1 	CQG Net/LAN 1
2824 	udp 	cqg-netlan-1 	CQG Net/Lan 1
2825 			(unassigned) Possibly assigned
2826 	tcp 	slc-systemlog 	slc systemlog
2826 	udp 	slc-systemlog 	slc systemlog
2827 	tcp 	slc-ctrlrloops 	slc ctrlrloops
2827 	udp 	slc-ctrlrloops 	slc ctrlrloops
2828 	tcp 	itm-lm 	ITM License Manager
2828 	udp 	itm-lm 	ITM License Manager
2829 	tcp 	silkp1 	silkp1
2829 	udp 	silkp1 	silkp1
2830 	tcp 	silkp2 	silkp2
2830 	udp 	silkp2 	silkp2
2831 	tcp 	silkp3 	silkp3
2831 	udp 	silkp3 	silkp3
2832 	tcp 	silkp4 	silkp4
2832 	udp 	silkp4 	silkp4
2833 	tcp 	glishd 	glishd
2833 	udp 	glishd 	glishd
2834 	tcp 	evtp 	EVTP
2834 	udp 	evtp 	EVTP
2835 	tcp 	evtp-data 	EVTP-DATA
2835 	udp 	evtp-data 	EVTP-DATA
2836 	tcp 	catalyst 	catalyst
2836 	udp 	catalyst 	catalyst
2837 	tcp 	repliweb 	Repliweb
2837 	udp 	repliweb 	Repliweb
2838 	tcp 	starbot 	Starbot
2838 	udp 	starbot 	Starbot
2839 	tcp 	nmsigport 	NMSigPort
2839 	udp 	nmsigport 	NMSigPort
2840 	tcp 	l3-exprt 	l3-exprt
2840 	udp 	l3-exprt 	l3-exprt
2841 	tcp 	l3-ranger 	l3-ranger
2841 	udp 	l3-ranger 	l3-ranger
2842 	tcp 	l3-hawk 	l3-hawk
2842 	udp 	l3-hawk 	l3-hawk
2843 	tcp 	pdnet 	PDnet
2843 	udp 	pdnet 	PDnet
2844 	tcp 	bpcp-poll 	BPCP POLL
2844 	udp 	bpcp-poll 	BPCP POLL
2845 	tcp 	bpcp-trap 	BPCP TRAP
2845 	udp 	bpcp-trap 	BPCP TRAP
2846 	tcp 	aimpp-hello 	AIMPP Hello
2846 	udp 	aimpp-hello 	AIMPP Hello
2847 	tcp 	aimpp-port-req 	AIMPP Port Req
2847 	udp 	aimpp-port-req 	AIMPP Port Req
2848 	tcp 	amt-blc-port 	AMT-BLC-PORT
2848 	udp 	amt-blc-port 	AMT-BLC-PORT
2849 	tcp 	fxp 	FXP
2849 	udp 	fxp 	FXP
2850 	tcp 	metaconsole 	MetaConsole
2850 	udp 	metaconsole 	MetaConsole
2851 	tcp 	webemshttp 	webemshttp
2851 	udp 	webemshttp 	webemshttp
2852 	tcp 	bears-01 	bears-01
2852 	udp 	bears-01 	bears-01
2853 	tcp 	ispipes 	ISPipes
2853 	udp 	ispipes 	ISPipes
2854 	tcp 	infomover 	InfoMover
2854 	udp 	infomover 	InfoMover
2855 	tcp 	msrp 	MSRP over TCP
2855 	udp 		Reserved
2856 	tcp 	cesdinv 	cesdinv
2856 	udp 	cesdinv 	cesdinv
2857 	tcp 	simctlp 	SimCtIP
2857 	udp 	simctlp 	SimCtIP
2858 	tcp 	ecnp 	ECNP
2858 	udp 	ecnp 	ECNP
2859 	tcp 	activememory 	Active Memory
2859 	udp 	activememory 	Active Memory
2860 	tcp 	dialpad-voice1 	Dialpad Voice 1
2860 	udp 	dialpad-voice1 	Dialpad Voice 1
2861 	tcp 	dialpad-voice2 	Dialpad Voice 2
2861 	udp 	dialpad-voice2 	Dialpad Voice 2
2862 	tcp 	ttg-protocol 	TTG Protocol
2862 	udp 	ttg-protocol 	TTG Protocol
2863 	tcp 	sonardata 	Sonar Data
2863 	udp 	sonardata 	Sonar Data
2864 	tcp 	astromed-main 	main 5001 cmd
2864 	udp 	astromed-main 	main 5001 cmd
2865 	tcp 	pit-vpn 	pit-vpn
2865 	udp 	pit-vpn 	pit-vpn
2866 	tcp 	iwlistener 	iwlistener
2866 	udp 	iwlistener 	iwlistener
2867 	tcp 	esps-portal 	esps-portal
2867 	udp 	esps-portal 	esps-portal
2868 	tcp 	npep-messaging 	Norman Proprietaqry Events Protocol
2868 	udp 	npep-messaging 	Norman Proprietaqry Events Protocol
2869 	tcp 	icslap 	ICSLAP
2869 	udp 	icslap 	ICSLAP
2870 	tcp 	daishi 	daishi
2870 	udp 	daishi 	daishi
2871 	tcp 	msi-selectplay 	MSI Select Play
2871 	udp 	msi-selectplay 	MSI Select Play
2872 	tcp 	radix 	RADIX
2872 	udp 	radix 	RADIX
2873 			Unassigned
2874 	tcp 	dxmessagebase1 	DX Message Base Transport Protocol
2874 	udp 	dxmessagebase1 	DX Message Base Transport Protocol
2875 	tcp 	dxmessagebase2 	DX Message Base Transport Protocol
2875 	udp 	dxmessagebase2 	DX Message Base Transport Protocol
2876 	tcp 	sps-tunnel 	SPS Tunnel
2876 	udp 	sps-tunnel 	SPS Tunnel
2877 	tcp 	bluelance 	BLUELANCE
2877 	udp 	bluelance 	BLUELANCE
2878 	tcp 	aap 	AAP
2878 	udp 	aap 	AAP
2879 	tcp 	ucentric-ds 	ucentric-ds
2879 	udp 	ucentric-ds 	ucentric-ds
2880 	tcp 	synapse 	Synapse Transport
2880 	udp 	synapse 	Synapse Transport
2881 	tcp 	ndsp 	NDSP
2881 	udp 	ndsp 	NDSP
2882 	tcp 	ndtp 	NDTP
2882 	udp 	ndtp 	NDTP
2883 	tcp 	ndnp 	NDNP
2883 	udp 	ndnp 	NDNP
2884 	tcp 	flashmsg 	Flash Msg
2884 	udp 	flashmsg 	Flash Msg
2885 	tcp 	topflow 	TopFlow
2885 	udp 	topflow 	TopFlow
2886 	tcp 	responselogic 	RESPONSELOGIC
2886 	udp 	responselogic 	RESPONSELOGIC
2887 	tcp 	aironetddp 	aironet
2887 	udp 	aironetddp 	aironet
2888 	tcp 	spcsdlobby 	SPCSDLOBBY
2888 	udp 	spcsdlobby 	SPCSDLOBBY
2889 	tcp 	rsom 	RSOM
2889 	udp 	rsom 	RSOM
2890 	tcp 	cspclmulti 	CSPCLMULTI
2890 	udp 	cspclmulti 	CSPCLMULTI
2891 	tcp 	cinegrfx-elmd 	CINEGRFX-ELMD License Manager
2891 	udp 	cinegrfx-elmd 	CINEGRFX-ELMD License Manager
2892 	tcp 	snifferdata 	SNIFFERDATA
2892 	udp 	snifferdata 	SNIFFERDATA
2893 	tcp 	vseconnector 	VSECONNECTOR
2893 	udp 	vseconnector 	VSECONNECTOR
2894 	tcp 	abacus-remote 	ABACUS-REMOTE
2894 	udp 	abacus-remote 	ABACUS-REMOTE
2895 	tcp 	natuslink 	NATUS LINK
2895 	udp 	natuslink 	NATUS LINK
2896 	tcp 	ecovisiong6-1 	ECOVISIONG6-1
2896 	udp 	ecovisiong6-1 	ECOVISIONG6-1
2897 	tcp 	citrix-rtmp 	Citrix RTMP
2897 	udp 	citrix-rtmp 	Citrix RTMP
2898 	tcp 	appliance-cfg 	APPLIANCE-CFG
2898 	udp 	appliance-cfg 	APPLIANCE-CFG
2899 	tcp 	powergemplus 	POWERGEMPLUS
2899 	udp 	powergemplus 	POWERGEMPLUS
2900 	tcp 	quicksuite 	QUICKSUITE
2900 	udp 	quicksuite 	QUICKSUITE
2901 	tcp 	allstorcns 	ALLSTORCNS
2901 	udp 	allstorcns 	ALLSTORCNS
2902 	tcp 	netaspi 	NET ASPI
2902 	udp 	netaspi 	NET ASPI
2903 	tcp 	suitcase 	SUITCASE
2903 	udp 	suitcase 	SUITCASE
2904 	tcp 	m2ua 	M2UA
2904 	udp 	m2ua 	M2UA
2904 	sctp 	m2ua 	M2UA
2905 	tcp 	m3ua 	M3UA
2905 	udp 		De-registered
2905 	sctp 	m3ua 	M3UA
2906 	tcp 	caller9 	CALLER9
2906 	udp 	caller9 	CALLER9
2907 	tcp 	webmethods-b2b 	WEBMETHODS B2B
2907 	udp 	webmethods-b2b 	WEBMETHODS B2B
2908 	tcp 	mao 	mao
2908 	udp 	mao 	mao
2909 	tcp 	funk-dialout 	Funk Dialout
2909 	udp 	funk-dialout 	Funk Dialout
2910 	tcp 	tdaccess 	TDAccess
2910 	udp 	tdaccess 	TDAccess
2911 	tcp 	blockade 	Blockade
2911 	udp 	blockade 	Blockade
2912 	tcp 	epicon 	Epicon
2912 	udp 	epicon 	Epicon
2913 	tcp 	boosterware 	Booster Ware
2913 	udp 	boosterware 	Booster Ware
2914 	tcp 	gamelobby 	Game Lobby
2914 	udp 	gamelobby 	Game Lobby
2915 	tcp 	tksocket 	TK Socket
2915 	udp 	tksocket 	TK Socket
2916 	tcp 	elvin-server 	Elvin Server
IANA assigned this well-formed service name as a replacement for “elvin_server”.
2916 	tcp 	elvin_server 	Elvin Server
2916 	udp 	elvin-server 	Elvin Server
IANA assigned this well-formed service name as a replacement for “elvin_server”.
2916 	udp 	elvin_server 	Elvin Server
2917 	tcp 	elvin-client 	Elvin Client
IANA assigned this well-formed service name as a replacement for “elvin_client”.
2917 	tcp 	elvin_client 	Elvin Client
2917 	udp 	elvin-client 	Elvin Client
IANA assigned this well-formed service name as a replacement for “elvin_client”.
2917 	udp 	elvin_client 	Elvin Client
2918 	tcp 	kastenchasepad 	Kasten Chase Pad
2918 	udp 	kastenchasepad 	Kasten Chase Pad
2919 	tcp 	roboer 	roboER
2919 	udp 	roboer 	roboER
2920 	tcp 	roboeda 	roboEDA
2920 	udp 	roboeda 	roboEDA
2921 	tcp 	cesdcdman 	CESD Contents Delivery Management
2921 	udp 	cesdcdman 	CESD Contents Delivery Management
2922 	tcp 	cesdcdtrn 	CESD Contents Delivery Data Transfer
2922 	udp 	cesdcdtrn 	CESD Contents Delivery Data Transfer
2923 	tcp 	wta-wsp-wtp-s 	WTA-WSP-WTP-S
2923 	udp 	wta-wsp-wtp-s 	WTA-WSP-WTP-S
2924 	tcp 	precise-vip 	PRECISE-VIP
2924 	udp 	precise-vip 	PRECISE-VIP
2925 			Unassigned (FRP-Released 12/7/00)
2926 	tcp 	mobile-file-dl 	MOBILE-FILE-DL
2926 	udp 	mobile-file-dl 	MOBILE-FILE-DL
2927 	tcp 	unimobilectrl 	UNIMOBILECTRL
2927 	udp 	unimobilectrl 	UNIMOBILECTRL
2928 	tcp 	redstone-cpss 	REDSTONE-CPSS
2928 	udp 	redstone-cpss 	REDSTONE-CPSS
2929 	tcp 	amx-webadmin 	AMX-WEBADMIN
2929 	udp 	amx-webadmin 	AMX-WEBADMIN
2930 	tcp 	amx-weblinx 	AMX-WEBLINX
2930 	udp 	amx-weblinx 	AMX-WEBLINX
2931 	tcp 	circle-x 	Circle-X
2931 	udp 	circle-x 	Circle-X
2932 	tcp 	incp 	INCP
2932 	udp 	incp 	INCP
2933 	tcp 	4-tieropmgw 	4-TIER OPM GW
2933 	udp 	4-tieropmgw 	4-TIER OPM GW
2934 	tcp 	4-tieropmcli 	4-TIER OPM CLI
2934 	udp 	4-tieropmcli 	4-TIER OPM CLI
2935 	tcp 	qtp 	QTP
2935 	udp 	qtp 	QTP
2936 	tcp 	otpatch 	OTPatch
2936 	udp 	otpatch 	OTPatch
2937 	tcp 	pnaconsult-lm 	PNACONSULT-LM
2937 	udp 	pnaconsult-lm 	PNACONSULT-LM
2938 	tcp 	sm-pas-1 	SM-PAS-1
2938 	udp 	sm-pas-1 	SM-PAS-1
2939 	tcp 	sm-pas-2 	SM-PAS-2
2939 	udp 	sm-pas-2 	SM-PAS-2
2940 	tcp 	sm-pas-3 	SM-PAS-3
2940 	udp 	sm-pas-3 	SM-PAS-3
2941 	tcp 	sm-pas-4 	SM-PAS-4
2941 	udp 	sm-pas-4 	SM-PAS-4
2942 	tcp 	sm-pas-5 	SM-PAS-5
2942 	udp 	sm-pas-5 	SM-PAS-5
2943 	tcp 	ttnrepository 	TTNRepository
2943 	udp 	ttnrepository 	TTNRepository
2944 	tcp 	megaco-h248 	Megaco H-248
2944 	udp 	megaco-h248 	Megaco H-248
2944 	sctp 	megaco-h248 	Megaco-H.248 text
2945 	tcp 	h248-binary 	H248 Binary
2945 	udp 	h248-binary 	H248 Binary
2945 	sctp 	h248-binary 	Megaco/H.248 binary
2946 	tcp 	fjsvmpor 	FJSVmpor
2946 	udp 	fjsvmpor 	FJSVmpor
2947 	tcp 	gpsd 	GPS Daemon request/response protocol
2947 	udp 	gpsd 	GPS Daemon request/response protocol
2948 	tcp 	wap-push 	WAP PUSH
2948 	udp 	wap-push 	WAP PUSH
2949 	tcp 	wap-pushsecure 	WAP PUSH SECURE
2949 	udp 	wap-pushsecure 	WAP PUSH SECURE
2950 	tcp 	esip 	ESIP
2950 	udp 	esip 	ESIP
2951 	tcp 	ottp 	OTTP
2951 	udp 	ottp 	OTTP
2952 	tcp 	mpfwsas 	MPFWSAS
2952 	udp 	mpfwsas 	MPFWSAS
2953 	tcp 	ovalarmsrv 	OVALARMSRV
2953 	udp 	ovalarmsrv 	OVALARMSRV
2954 	tcp 	ovalarmsrv-cmd 	OVALARMSRV-CMD
2954 	udp 	ovalarmsrv-cmd 	OVALARMSRV-CMD
2955 	tcp 	csnotify 	CSNOTIFY
2955 	udp 	csnotify 	CSNOTIFY
2956 	tcp 	ovrimosdbman 	OVRIMOSDBMAN
2956 	udp 	ovrimosdbman 	OVRIMOSDBMAN
2957 	tcp 	jmact5 	JAMCT5
2957 	udp 	jmact5 	JAMCT5
2958 	tcp 	jmact6 	JAMCT6
2958 	udp 	jmact6 	JAMCT6
2959 	tcp 	rmopagt 	RMOPAGT
2959 	udp 	rmopagt 	RMOPAGT
2960 	tcp 	dfoxserver 	DFOXSERVER
2960 	udp 	dfoxserver 	DFOXSERVER
2961 	tcp 	boldsoft-lm 	BOLDSOFT-LM
2961 	udp 	boldsoft-lm 	BOLDSOFT-LM
2962 	tcp 	iph-policy-cli 	IPH-POLICY-CLI
2962 	udp 	iph-policy-cli 	IPH-POLICY-CLI
2963 	tcp 	iph-policy-adm 	IPH-POLICY-ADM
2963 	udp 	iph-policy-adm 	IPH-POLICY-ADM
2964 	tcp 	bullant-srap 	BULLANT SRAP
2964 	udp 	bullant-srap 	BULLANT SRAP
2965 	tcp 	bullant-rap 	BULLANT RAP
2965 	udp 	bullant-rap 	BULLANT RAP
2966 	tcp 	idp-infotrieve 	IDP-INFOTRIEVE
2966 	udp 	idp-infotrieve 	IDP-INFOTRIEVE
2967 	tcp 	ssc-agent 	SSC-AGENT
2967 	udp 	ssc-agent 	SSC-AGENT
2968 	tcp 	enpp 	ENPP
2968 	udp 	enpp 	ENPP
2969 	tcp 	essp 	ESSP
2969 	udp 	essp 	ESSP
2970 	tcp 	index-net 	INDEX-NET
2970 	udp 	index-net 	INDEX-NET
2971 	tcp 	netclip 	NetClip clipboard daemon
2971 	udp 	netclip 	NetClip clipboard daemon
2972 	tcp 	pmsm-webrctl 	PMSM Webrctl
2972 	udp 	pmsm-webrctl 	PMSM Webrctl
2973 	tcp 	svnetworks 	SV Networks
2973 	udp 	svnetworks 	SV Networks
2974 	tcp 	signal 	Signal
2974 	udp 	signal 	Signal
2975 	tcp 	fjmpcm 	Fujitsu Configuration Management Service
2975 	udp 	fjmpcm 	Fujitsu Configuration Management Service
2976 	tcp 	cns-srv-port 	CNS Server Port
2976 	udp 	cns-srv-port 	CNS Server Port
2977 	tcp 	ttc-etap-ns 	TTCs Enterprise Test Access Protocol – NS
2977 	udp 	ttc-etap-ns 	TTCs Enterprise Test Access Protocol – NS
2978 	tcp 	ttc-etap-ds 	TTCs Enterprise Test Access Protocol – DS
2978 	udp 	ttc-etap-ds 	TTCs Enterprise Test Access Protocol – DS
2979 	tcp 	h263-video 	H.263 Video Streaming
2979 	udp 	h263-video 	H.263 Video Streaming
2980 	tcp 	wimd 	Instant Messaging Service
2980 	udp 	wimd 	Instant Messaging Service
2981 	tcp 	mylxamport 	MYLXAMPORT
2981 	udp 	mylxamport 	MYLXAMPORT
2982 	tcp 	iwb-whiteboard 	IWB-WHITEBOARD
2982 	udp 	iwb-whiteboard 	IWB-WHITEBOARD
2983 	tcp 	netplan 	NETPLAN
2983 	udp 	netplan 	NETPLAN
2984 	tcp 	hpidsadmin 	HPIDSADMIN
2984 	udp 	hpidsadmin 	HPIDSADMIN
2985 	tcp 	hpidsagent 	HPIDSAGENT
2985 	udp 	hpidsagent 	HPIDSAGENT
2986 	tcp 	stonefalls 	STONEFALLS
2986 	udp 	stonefalls 	STONEFALLS
2987 	tcp 	identify 	identify
2987 	udp 	identify 	identify
2988 	tcp 	hippad 	HIPPA Reporting Protocol
2988 	udp 	hippad 	HIPPA Reporting Protocol
2989 	tcp 	zarkov 	ZARKOV Intelligent Agent Communication
2989 	udp 	zarkov 	ZARKOV Intelligent Agent Communication
2990 	tcp 	boscap 	BOSCAP
2990 	udp 	boscap 	BOSCAP
2991 	tcp 	wkstn-mon 	WKSTN-MON
2991 	udp 	wkstn-mon 	WKSTN-MON
2992 	tcp 	avenyo 	Avenyo Server
2992 	udp 	avenyo 	Avenyo Server
2993 	tcp 	veritas-vis1 	VERITAS VIS1
2993    udp 	veritas-vis1 	VERITAS VIS1
2994 	tcp 	veritas-vis2 	VERITAS VIS2
2994 	udp 	veritas-vis2 	VERITAS VIS2
2995 	tcp 	idrs 	IDRS
2995 	udp 	idrs 	IDRS
2996    tcp 	vsixml 	vsixml
2996 	udp 	vsixml 	vsixml
2997 	tcp 	rebol 	REBOL
2997 	udp 	rebol 	REBOL
2998 	tcp 	realsecure 	Real Secure
2998 	udp 	realsecure 	Real Secure
2999 	tcp 	remoteware-un 	RemoteWare Unassigned
2999 	udp 	remoteware-un 	RemoteWare Unassigned
3389 	tcp 	RPD/WBT 	Microsoft Terminal Server (RDP) officially registered as Windows Based Terminal (WBT)
3389 	udp 	RPD/WBT 	Microsoft Terminal Server (RDP) officially registered as Windows Based Terminal (WBT)
6697 	tcp 	IRC SSL 	Secure Internet Relay Chat—often used
3306 	tcp 	MySQL 	MySQL database system
5555 	tcp 	freeciv
"""

    import sqlite3
    import os
    import getpass
    import time
    
    database = sqlite3.connect("EtquamorPSDatabase.db")
    databaseCursor = database.cursor()
    databaseCursor.execute("CREATE TABLE IF NOT EXISTS etquamorportscanner('port', 'tcp_udp', 'nameOfService', 'descriptionOfService')")
    database.close()
    print("\n[#] It will take approximately 10 minutes, Please Wait...\n")
    startingTime = time.time()
    for i in ports.splitlines():
        dataLine = str(i).split(" \t",4)
        database = sqlite3.connect("EtquamorPSDatabase.db")
        databaseCursor = database.cursor()
        if len(dataLine)==1:
            databaseCursor.execute("INSERT INTO etquamorportscanner VALUES (?, ?, ?, ?)",(dataLine[0],"","","")) 
        elif len(dataLine)==2:
            databaseCursor.execute("INSERT INTO etquamorportscanner VALUES (?, ?, ?, ?)",(dataLine[0],dataLine[1],"","")) 
        elif len(dataLine)==3:
            databaseCursor.execute("INSERT INTO etquamorportscanner VALUES (?, ?, ?, ?)",(dataLine[0],dataLine[1],dataLine[2],""))
        elif len(dataLine)==4:
            databaseCursor.execute("INSERT INTO etquamorportscanner VALUES (?, ?, ?, ?)",(dataLine[0],dataLine[1],dataLine[2],dataLine[3]))
        database.commit()
    print("[*] Database Succesfuly Created!\n\nTotal Create time =>",(str(time.time()-startingTime).split(".", 1)[0]+"."+str(time.time()-startingTime).split(".", 1)[1][0:3]),"Seconds","\n\n")
    time.sleep(1.5)

def askForCreateDatabase():
    print("\n[#] It seems you don't have port database.\n[#] You can't see any information about ports without database.\n[#] Do you want download database (It will download automatically) [Y/n]\n")
    while True:
        verifyDatabaseCreate = input("==>")
        verifyDatabaseCreate = str(str(verifyDatabaseCreate).lower()).strip()
        if verifyDatabaseCreate=="y":
            createDatabase()
            return True
        elif verifyDatabaseCreate=="n":
            return False
        else:
            print("\n[#]",verifyDatabaseCreate,"is not a option.\n")
            continue