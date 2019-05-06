#####################################
####    KLASYFIKATOR BAYESA      ####
####    TEST KLASYFIKACJI DNS    ####
####      Artur M. Brodzki       ####
#####################################

setwd("/Users/artur/Projekty/kant-security/ips_dns_tunnel/bayes/")
source("train.r")

######################
# Poprawne zapytania #
######################

validDns.csv <- read.csv(file = "data/valid-queries.csv", header = FALSE)
validDns.domains = validDns.csv$V2
connVQ2 <- file("data/valid-queries-2.txt", open = "r")
validDns.domains2 = readLines(connVQ2)
close(connVQ2)

######################
# Z³oœliwe zapytania #
######################

connHEX <- file("data/evil-queries-hex.txt", open = "r")
connB32 <- file("data/evil-queries-base32.txt", open = "r")
evilDns.domainsHEX = readLines(connHEX)
evilDns.domainsB32 = readLines(connB32)
close(connHEX)
close(connB32)

#############################
# Wczytywanie klasyfikatora #
#############################

totalDns.ngrams.frame <- read.table(
  file = "dns.freqs", sep = ","
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

#########
# Testy #
#########

testDnsBayes <- function(validSample, evilSample, ngrams, queryLen = 8, lenThr = 3, sampleSize = 5000) {
  
  testDns.truePositives = 0;
  testDns.trueNegatives = 0;
  testDns.falsePositives = 0;
  testDns.falseNegatives = 0;
  testDns.validSample = sample(validSample, sampleSize)
  testDns.evilSample = sample(evilSample, sampleSize)
  
  print("Checking valid class...")
  testDns.i = 0
  testDns.pb = txtProgressBar(min = 0, 
                              max = length(testDns.validSample), 
                              initial = 0)
  for(d in testDns.validSample) {
    if(isValidDns(d, ngrams, lenThr = lenThr)) {
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
  testDns.pb = txtProgressBar(min = 0, 
                              max = length(testDns.evilSample), 
                              initial = 0)
  for(d in testDns.evilSample) {
    if(! isValidDns(d, ngrams, lenThr = lenThr)) {
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

printFalsePositives <- function(validSample, ngrams, lenThr = 3, sampleSize = 10000) {

  testDns.validSample = sample(validSample, sampleSize)
  for(d in testDns.validSample) {
    if(! isValidDns(d, ngrams, lenThr = lenThr)) {
      print(paste0(d))
    }
  }
  
}

printFalsePositives(unique(validDns.polishDomains), 
                    dnsBayes.ngrams, 
                    sampleSize = length(unique(validDns.polishDomains)))

testDnsBayes(validDns.domains, 
             evilDns.domains2, 
             dnsBayes.ngrams,
             queryLen = 8, 
             lenThr = 3, 
             sampleSize = 5000)
