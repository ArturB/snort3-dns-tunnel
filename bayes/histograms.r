#####################################
####    KLASYFIKATOR BAYESA      ####
####       HISTOGRAMY DNS        ####
####      Artur M. Brodzki       ####
#####################################

library(rjson)

allSubStrings <- function(str, n = 3) {
  substring(str, 1:(nchar(str)-n+1), n:nchar(str))
}

setwd("/Users/artur/Projekty/kant-security/bayes/")

######################
# Poprawne zapytania #
######################

validDns.csv <- read.csv(file = "valid-queries.csv", header = FALSE)
validDns.domains = validDns.csv$V2
connVQ2 <- file("valid-queries-2.txt", open = "r")
validDns.domains2 = readLines(connVQ2)
close(connVQ2)

######################
# Histogram d³ugoœci #
######################

validDns.lengths = 1:length(validDns.domains)
validDns.i = 0
validDns.pb =  txtProgressBar(min = 0, max = length(validDns.domains), initial = 0)
for(i in 1:length(validDns.domains)) {
  validDns.lengths[[i]] = nchar(toString(validDns.domains[[i]]))
  validDns.i = validDns.i + 1
  setTxtProgressBar(validDns.pb, validDns.i)
}
close(validDns.pb)
hist(validDns.lengths, breaks = 63, col = "red", freq = FALSE, ylim=c(0, 0.3), xlim = range(1:40))


######################
# Histogram wartoœci #
######################

isValidDnsProb <- function(d, allNgrams, lenThr = 5) {
  if(nchar(d) < lenThr) {
    return(100)
  }
  subs <- allSubStrings(d, 3)
  prob = 0;
  for(s in subs) {
    if(! s %in% names(allNgrams)) {
      return(100)
    }
    else {
      prob = prob + allNgrams[[s]]
    }
  }
  return(prob)
}

testDns.validValues = 1:length(validDns.domains)
testDns.i = 0
testDns.pb = txtProgressBar(min = 0, max = length(validDns.domains), initial = 0)
for(i in 1:length(validDns.domains)) {
  testDns.validValues[[i]] = isValidDnsProb(toString(validDns.domains[[i]]), totalDns.ngrams)
  testDns.i = testDns.i + 1
  setTxtProgressBar(testDns.pb, testDns.i)
}
close(testDns.pb)
hist(testDns.validValues, breaks = 5000, col = "red", freq = FALSE, xlim = range(1:110))




