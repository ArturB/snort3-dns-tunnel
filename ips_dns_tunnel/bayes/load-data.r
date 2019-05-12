#####################################
####    KLASYFIKATOR BAYESA      ####
####       DNS TUNNELLING        ####
####      LaDOWANIE DANYCH       ####
####      Artur M. Brodzki       ####
#####################################

setwd("/Users/artur/Projekty/kant-security/ips_dns_tunnel/bayes/")

######################
# Poprawne zapytania #
######################

validDns.csv.casualTraffic = read.csv(file = "data/casual-traffic.csv", header = FALSE)
validDns.csv.homeTraffic   = read.csv(file = "data/home-traffic.csv",   header = FALSE)
validDns.csv.otherTraffic  = read.csv(file = "data/other-traffic.csv",  header = FALSE)
validDns.csv.publicWifi    = read.csv(file = "data/public-wifi.csv",    header = FALSE)
validDns.domains.casualTraffic = sample(validDns.csv.casualTraffic$V2,100000)
validDns.domains.homeTraffic   = sample(validDns.csv.homeTraffic$V2,100000)
validDns.domains.otherTraffic  = sample(validDns.csv.otherTraffic$V2,50000)
validDns.domains.publicWifi    = sample(validDns.csv.publicWifi$V2,200000)
validDns.domains = c( sapply(validDns.domains.casualTraffic,toString),
                      sapply(validDns.domains.homeTraffic,toString), 
                      sapply(validDns.domains.otherTraffic,toString),
                      sapply(validDns.domains.publicWifi,toString)
                   )
validDns.domains = validDns.domains[nchar(validDns.domains) >= 3]
validDns.domains = sample(validDns.domains)

connPL <- file("data/polish-traffic.txt", open = "r")
validDns.polishDomains = readLines(connPL)
close(connPL)
validDns.polishDomains = validDns.polishDomains[nchar(validDns.polishDomains) >= 3]
validDns.polishDomains = sample(validDns.polishDomains)

######################
# Zlosliwe zapytania #
######################

connHEX <- file("data/hex-traffic.txt", open = "r")
connB32 <- file("data/b32-traffic.txt", open = "r")
evilDns.domainsHEX = readLines(connHEX)
evilDns.domainsB32 = readLines(connB32)
close(connHEX)
close(connB32)

evilDns.domains = c( sample(evilDns.domainsHEX,10000), 
                     sample(evilDns.domainsB32,10000) 
                  )
evilDns.domains = sample(evilDns.domains)

evilDns.domains2 = c( sample(evilDns.domainsHEX,10000), 
                     sample(evilDns.domainsB32,10000) 
)
evilDns.domains2 = sample(evilDns.domains2)

