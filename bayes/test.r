#####################################
####    KLASYFIKATOR BAYESA      ####
####    TEST KLASYFIKACJI DNS    ####
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
# Z³oœliwe zapytania #
######################

connHEX <- file("evil-queries-hex.txt", open = "r")
connB32 <- file("evil-queries-base32.txt", open = "r")
evilDns.domainsHEX = readLines(connHEX)
evilDns.domainsB32 = readLines(connB32)
close(connHEX)
close(connB32)

#############################
# Wczytywanie klasyfikatora #
#############################

totalDns.ngrams.frame <- read.table(
  file = "dns.freqs"
)
totalDns.ngrams = as.list(setNames(totalDns.ngrams.frame$V2, totalDns.ngrams.frame$V1))

##################################
####  Testy klasyfikatora     ####
##################################

isValidDns <- function(d, allNgrams, lenThr = 3, probThr = 0) {
  if(nchar(d) < lenThr) {
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

##################
# Testy w³aœciwe #
##################

testDnsBayes <- function(queryLen = 8, lenThr = 3, sampleSize = 5000) {
  
  testDns.truePositives = 0;
  testDns.trueNegatives = 0;
  testDns.falsePositives = 0;
  testDns.falseNegatives = 0;
  testDns.validSample = sample(c( sample(validDns.domains, sampleSize / 2), sample(validDns.domains2, sampleSize / 2) ))
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
    if(! isValidDns(toString(substring(d, 10, queryLen+9)), totalDns.ngrams, lenThr = lenThr)) {
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

##########################
# Listuj False-Positives #
##########################

printFalsePositives <- function(lenThr = 3, sampleSize = 10000) {

  testDns.validSample = sample(validDns.domains2, sampleSize)
  for(d in testDns.validSample) {
    if(! isValidDns(toString(d), totalDns.ngrams, lenThr = lenThr)) {
      print(paste0("False positive: ", d))
    }
  }
  
}

testDnsBayes(queryLen = 8, lenThr = 3, sampleSize = 8000)
