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

binsearch <- function(list, range, )

#####################################
####     Poprawne zapytania      ####
#####################################

validDns.csv <- read.csv(file = "valid-queries.csv", header = FALSE)
validDns.domains = validDns.csv$V2

######################
# Histogram długości #
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

#############
# Częstości #
#############

validDns.ngrams = list()
validDns.pb = txtProgressBar(min = 0, max = length(validDns.domains), initial = 0)
validDns.i = 0
validDns.nsubs = 0;
for(d in validDns.domains) {
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

#####################################
####     Złośliwe zapytania      ####
#####################################

connHEX <- file("evil-queries-hex.txt", open = "r")
connB32 <- file("evil-queries-base32.txt", open = "r")
evilDns.domainsHEX = readLines(connHEX)
evilDns.domainsB32 = readLines(connB32)
close(connHEX)
close(connB32)
evilDns.ngrams = list()
evilDns.i = 0
evilDns.nsubs = 0
evilDns.pb = txtProgressBar(min = 0, max = length(evilDns.domainsHEX) + length(evilDns.domainsB32), initial = 0)
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
for(ng in names(evilDns.ngrams)) {
  evilDns.ngrams[[ng]] = log( evilDns.ngrams[[ng]] / evilDns.nsubs, base = 2 )
}
evilDns.ngrams = evilDns.ngrams[order(unlist(evilDns.ngrams), decreasing = TRUE)]

#####################################
####  Baza prawdopodobieństw     ####
#####################################

totalDns.names = c( names(validDns.ngrams), names(evilDns.ngrams) )
totalDns.ngrams = list()

# Because cost of false negative 
# is many times higher then cost of false positive,
# probability scaling factor is introduced.
# It specifies, how many times 
# is probability of negative class higher 
# than probability of positive class
# to classify query as negative. 
totalDns.factor = 64 

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
  col.names = FALSE
)

##################################
####  Testy klasyfikatora     ####
##################################

isValidDns <- function(d, allNgrams, lenThr = 3, probThr = 0) {
  if(nchar(d) <= lenThr) {
    return(TRUE);
  }
  subs <- allSubStrings(d, 3)
  prob = 0;
  for(s in subs) {
    if(! s %in% names(allNgrams)) {
      return(TRUE)
    }
    else {
      prob = prob + allNgrams[[s]]
    }
  }
  return(prob > probThr)
}

isValidDnsProb <- function(d, allNgrams, lenThr = 5) {
  if(nchar(d) <= lenThr) {
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

printFalseNegatives <- function(sample, ngrams) {
  for(d in sample) {
    if(! isValidDns(toString(d), ngrams)) {
      print(paste0("False-negative: ", d))
    }
  }
}


#####################
# Histogram Validów #
#####################

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

##################
# Testy właściwe #
##################

testDnsBayes <- function(queryLen = 8, lenThr = 3, sampleSize = 10000) {
  
  testDns.truePositives = 0;
  testDns.trueNegatives = 0;
  testDns.falsePositives = 0;
  testDns.falseNegatives = 0;
  testDns.validSample = sample(validDns.domains, sampleSize)
  testDns.evilSample = sample(c( evilDns.domainsHEX, evilDns.domainsB32 ), sampleSize)
  
  print("Checking valid class...")
  testDns.i = 0
  testDns.pb = txtProgressBar(min = 0, max = length(testDns.validSample), initial = 0)
  for(d in testDns.validSample) {
    if(isValidDns(toString(d), totalDns.ngrams, lenThr = lenThr)) {
      testDns.truePositives = testDns.truePositives + 1
    }
    else {
      testDns.falseNegatives = testDns.falseNegatives + 1
      #print(paste0("False-negative: ", d))
    }
    testDns.i = testDns.i + 1
    setTxtProgressBar(testDns.pb, testDns.i)
  }
  close(testDns.pb)
  testDns.truePositives = testDns.truePositives / length(testDns.validSample)
  testDns.falseNegatives = testDns.falseNegatives / length(testDns.validSample)
  
  print("Checking evil class...")
  testDns.i = 0
  testDns.pb = txtProgressBar(min = 0, max = length(testDns.evilSample), initial = 0)
  for(d in testDns.evilSample) {
    if(! isValidDns(toString(substring(d, 1, queryLen)), totalDns.ngrams, lenThr = lenThr)) {
      testDns.trueNegatives = testDns.trueNegatives + 1
    }
    else {
      testDns.falsePositives = testDns.falsePositives + 1
    }
    testDns.i = testDns.i + 1
    setTxtProgressBar(testDns.pb, testDns.i)
  }
  close(testDns.pb)
  testDns.trueNegatives = testDns.trueNegatives / length(testDns.evilSample)
  testDns.falsePositives = testDns.falsePositives / length(testDns.evilSample)
  
  print(paste0("True VALID-DNS rate:    ", round(10000 * testDns.truePositives)/100, "%" ))
  print(paste0("True INVALID-DNS rate:  ", round(10000 * testDns.trueNegatives)/100, "%" ))
  print(paste0("False VALID-DNS rate:   ", round(10000 * testDns.falsePositives)/100, "%" ))
  print(paste0("False INVALID-DNS rate: ", round(10000 * testDns.falseNegatives)/100, "%" ))
  
}





