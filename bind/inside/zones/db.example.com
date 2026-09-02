$TTL 3600
@   IN  SOA  ns1.example.com. hostmaster.example.com. (
                2026090201 ; serial (YYYYMMDDnn)
                3600       ; refresh
                900        ; retry
                1209600    ; expire
                3600 )     ; minimum

    IN  NS   ns1.example.com.
    IN  NS   ns2.example.com.

ns1 IN  A    10.0.0.1
ns2 IN  A    10.0.0.2
www IN  A    203.0.113.10
mail IN A    203.0.113.20
