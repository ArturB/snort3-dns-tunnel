#####################################
####    KLASYFIKATOR BAYESA      ####
####       DNS TUNNELLING       ####
####      Artur M. Brodzki       ####
#####################################

library(rjson)

#####################################
####    Przygotowanie danych     ####
#####################################

setwd("/Users/artur/Projekty/kant-security/bayes/")
dnsQueries <- fromJSON(file = "qlog.json")
dnsFrame <- as.data.frame(dnsQueries)
print(dnsQueries[[2]][[2]][[1]])
length(dnsQueries[[1]])

dnsCSV = data.frame( matrix(nrow = length(dnsQueries), ncol = length(dnsQueries[[1]])) )
rowsCSV = length(dnsQueries)
colsCSV = length(dnsQueries[[1]])
for (i in range(1, rowsCSV)) {
  for(j in range(1,colsCSV)) {
    dnsCSV[[i,j]] = dnsQueries[[i]][[j]][[2]][[1]]
  }
}

dnsDomains = read.csv(file = "qlog.csv", sep = ',', header = FALSE)
domains = dnsDomains[[2]]
write.csv(file = "domeny.csv", domains)
length(domains)
