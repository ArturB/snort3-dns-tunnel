#####################################
####    KLASYFIKATOR BAYESA      ####
####       DNS TUNNELLING        ####
####      Artur M. Brodzki       ####
#####################################

library(rjson)

allSubStrings <- function(str, n = 3) {
  substring(str, 1:(nchar(str)-n+1), n:nchar(str))
}

setwd("/Users/artur/Projekty/kant-security/bayes/")

############################
#### Poprawne zapytania ####
############################

validDns.csv <- read.csv(file = "valid-queries.csv", header = FALSE)
validDns.domains = validDns.csv$V2
connVQ2 <- file("valid-queries-2.txt", open = "r")
validDns.domains2 = readLines(connVQ2)
close(connVQ2)
validDns.SetsScalingFactor = round(length(validDns.domains) / length(validDns.domains2))

validDns.ngrams = list()
validDns.pb = txtProgressBar(
  min = 0, 
  max = length(validDns.domains) + length(validDns.domains2) * validDns.SetsScalingFactor, 
  initial = 0)
validDns.i = 0
validDns.nsubs = 0;
for(d in c( validDns.domains, rep(validDns.domains2, validDns.SetsScalingFactor))) {
  for(ng in allSubStrings(d, 3)) {
    if(ng %in% names(validDns.ngrams)) {
      validDns.ngrams[[ng]] = validDns.ngrams[[ng]] + 1.0
    }
    else {
      validDns.ngrams[[ng]] = 1.0
    }
  }
  validDns.i = validDns.i + 1
  validDns.nsubs = validDns.nsubs + length(allSubStrings(d, 3))
  setTxtProgressBar(validDns.pb, validDns.i)
}
close(validDns.pb)
for(ng in names(validDns.ngrams)) {
  validDns.ngrams[[ng]] = log( validDns.ngrams[[ng]] / validDns.nsubs, base = 2 )
}
validDns.ngrams = validDns.ngrams[order(unlist(validDns.ngrams), decreasing = TRUE)]
validDns.ngrams = validDns.ngrams[names(validDns.ngrams) != ""]
validDns.ngrams = validDns.ngrams[nchar(names(validDns.ngrams)) == 3]

############################
#### Złośliwe zapytania ####
############################

connHEX <- file("evil-queries-hex.txt", open = "r")
connB32 <- file("evil-queries-base32.txt", open = "r")
evilDns.domainsHEX = head(readLines(connHEX),2000)
evilDns.domainsB32 = head(readLines(connB32),2000)
close(connHEX)
close(connB32)
evilDns.ngrams = list()
evilDns.i = 0
evilDns.nsubs = 0
evilDns.pb = txtProgressBar(
  min = 0, 
  max = length(evilDns.domainsHEX) + length(evilDns.domainsB32), 
  initial = 0)
for(d in c( evilDns.domainsHEX, evilDns.domainsB32 )) {
  for(ng in allSubStrings(d, 3)) {
    if(ng %in% names(evilDns.ngrams)) {
      evilDns.ngrams[[ng]] = evilDns.ngrams[[ng]] + 1.0
    }
    else {
      evilDns.ngrams[[ng]] = 1.0
    }
  }
  evilDns.i = evilDns.i + 1
  evilDns.nsubs = evilDns.nsubs + length(allSubStrings(d, 3))
  setTxtProgressBar(evilDns.pb, evilDns.i)
}
close(evilDns.pb)
evilDns.pb = txtProgressBar(
  min = 0, 
  max = length(evilDns.ngrams), 
  initial = 0)
evilDns.i = 0
for(ng in names(evilDns.ngrams)) {
  evilDns.ngrams[[ng]] = log( evilDns.ngrams[[ng]] / evilDns.nsubs, base = 2 )
  evilDns.i = evilDns.i + 1
  setTxtProgressBar(evilDns.pb, evilDns.i)
}
close(evilDns.pb)
evilDns.ngrams = evilDns.ngrams[order(unlist(evilDns.ngrams), decreasing = TRUE)]

######################
#### Baza ngramów ####
######################

totalDns.names = c( names(validDns.ngrams), names(evilDns.ngrams) )
totalDns.ngrams = list()

# Because cost of false negative 
# is many times higher then cost of false positive,
# probability scaling factor is introduced.
# It specifies, how many times 
# is probability of negative class higher 
# than probability of positive class
# to classify query as negative. 
totalDns.factor = 20

totalDns.i = 0
totalDns.pb = txtProgressBar(min = 0, max = length(totalDns.names), initial = 0)
for(n in totalDns.names) {
  # ONLY-EVIL VASE
  if(! n %in% names(validDns.ngrams)) {
    totalDns.ngrams[[n]] = -20
  }
  # ONLY-VALID CASE
  else if(! n %in% names(evilDns.ngrams)) {
    totalDns.ngrams[[n]] = 20
  }
  # BOTH-VALID CASE
  else {
    totalDns.ngrams[[n]] = validDns.ngrams[[n]] - evilDns.ngrams[[n]] + log(totalDns.factor, base = 2)
  }
  totalDns.i = totalDns.i + 1
  setTxtProgressBar(totalDns.pb, totalDns.i)
}
close(totalDns.pb)
totalDns.ngrams = totalDns.ngrams[order(names(totalDns.ngrams), decreasing = FALSE)]
totalDns.ngrams.frame = data.frame(
  ngram = names( totalDns.ngrams),
  prob  = unlist(totalDns.ngrams)
)
write.table(
  x = totalDns.ngrams.frame, 
  file = "dns.freqs", 
  quote = FALSE, 
  row.names = FALSE, 
  col.names = FALSE,
  sep = ","
)



