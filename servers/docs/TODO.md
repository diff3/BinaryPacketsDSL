TODO

🔴 Säkerhet (ej implementerat)
	•	TLS/SSL-stöd
	•	Kryptera trafik mellan klient ↔ proxy
	•	Kräver certifikathantering
	•	Påverkar inspektionsmöjligheter (MITM)
	•	Autentisering / Auktorisering
	•	IP-whitelist
	•	API-nycklar
	•	Client-certifikat (mTLS)
	•	Skydd mot open-proxy-missbruk
	•	Explicit allow-list av klienter
	•	Policy-baserad access control

⸻

🟠 Prestanda & Skalning
	•	Async logging
	•	Queue-baserad loggning
	•	Separat logg-worker-tråd
	•	Minska disk-I/O i datapath
	•	Rate limiting
	•	Per-IP connection limits
	•	Token bucket / leaky bucket
	•	Skydd mot flood/DoS
	•	Event-driven I/O
	•	selectors / select / epoll
	•	Alternativ: asyncio-baserad implementation
	•	Minskad tråd-overhead
	•	Dynamisk buffer sizing
	•	Anpassa buffer efter trafiktyp
	•	Bättre throughput för bulk-data

⸻

🟡 Arkitektur & Struktur
	•	State dataclass
	•	Runtime-state (shutdown, toggles)
	•	Session-state (auth/world, encryption)
	•	Central sanningskälla
	•	Dependency injection
	•	Eliminera global CONFIG
	•	Möjliggör flera proxy-instanser per process
	•	Förbättrar testbarhet
	•	Controller / Management interface
	•	Telnet eller TCP-control port
	•	Live toggling av state
	•	Graceful shutdown triggers

⸻

🟢 Drift & Observability
	•	Metrics
	•	Aktiva connections
	•	Bytes in/out
	•	Errors per route
	•	Prometheus / StatsD
	•	Health checks
	•	Backend reachability
	•	Route status
	•	Self-health endpoint
	•	Log retention policy
	•	Automatisk cleanup
	•	Tidsbaserad rotation
	•	Disk-usage safeguards

⸻

🔵 Testning
	•	Integrationstester med riktiga sockets
	•	End-to-end trafik
	•	Verkliga backend-processer
	•	Concurrency / stress-tester
	•	1000+ samtidiga connections
	•	Long-running soak tests
	•	Shutdown under load
	•	Failure injection
	•	Backend disconnects
	•	Packet loss
	•	Partial writes

⸻

🧭 Medvetna designval (kommer ej implementeras just nu)
	•	Full production-proxy (HAProxy/Envoy-nivå)
	•	Automatisk cert-rotation
	•	L7-protokoll-medveten routing
	•	Komplett RBAC-system

⸻

📌 Projektets avsikt (påminnelse)

Denna proxy är avsedd för:
	•	✔️ Lokal utveckling
	•	✔️ Trafikinspektion
	•	✔️ Reverse engineering
	•	✔️ Offline analys
	•	❌ Internet-exponerad produktion

⸻

Om du vill, kan nästa steg vara:
	•	bryta ut denna TODO till docs/TODO.md
	•	eller märka varje punkt med effort (S/M/L) och risk