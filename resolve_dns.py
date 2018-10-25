# Resolve certificates for cert database.
import routing_aware_dns_resolver as rad

print(rad.lookupA("example.com"))
