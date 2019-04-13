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
