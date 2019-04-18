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
#### Z³oœliwe zapytania ####
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

#######################
# Histogram czêstoœci #
#######################

validDns.x <- 1:length(validDns.ngrams)
validDns.y <- unlist(validDns.ngrams)
plot(
  validDns.x, 
  validDns.y, 
  type = "n", 
  xlab = "Trójznaki (posortowane)", 
  ylab = "Prawdopodobieñstwo")
lines(
  validDns.x, 
  validDns.y, 
  col = "blue", 
  type = "l", 
  lwd = 1.5)

evilDns.x <- 1:length(evilDns.ngrams)
evilDns.y <- unlist(evilDns.ngrams)
lines(
  evilDns.x, 
  evilDns.y, 
  col = "red", 
  type = "l", 
  lwd = 1.5)

title("Histogram czêstoœci trójznaków")
legend(
  "topright",
  legend = c( "Poprawne zapytania", "Z³oœliwe zapytania" ), 
  col = c("blue", "red"), 
  lty = 1:2
)

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




