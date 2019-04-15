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

#####################################
####     Poprawne zapytania      ####
#####################################

validDns.csv <- read.csv(file = "valid-qlog.csv", header = FALSE)
validDns.domains = validDns.csv$V2

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
validDns.ngrams.frame = data.frame(
  ngram = names( validDns.ngrams),
  prob  = unlist(validDns.ngrams)
)
write.csv(x = validDns.ngrams.frame, file = "valid-freqs.csv", quote = FALSE, row.names = FALSE)

#####################################
####     Złośliwe zapytania      ####
#####################################

conn <- file("evil-qlog-small.txt", open = "r")
evilDns.domains = readLines(conn)
evilDns.ngrams = list()
evilDns.pb = txtProgressBar(min = 0, max = length(evilDns.domains), initial = 0)
evilDns.i = 0
evilDns.nsubs = 0
for(d in evilDns.domains) {
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
evilDns.ngrams.frame = data.frame(
  ngram = names( evilDns.ngrams),
  prob  = unlist(evilDns.ngrams)
)
write.csv(x = evilDns.ngrams.frame, file = "evil-freqs.csv", quote = FALSE, row.names = FALSE)

#####################################
####  Baza prawdopodobieństw     ####
#####################################

totalDns.names = c( names(validDns.ngrams), names(evilDns.ngrams) )
totalDns.ngrams = list()
totalDns.factor = 2
for(n in totalDns.names) {
  # ONLY-EVIL VASE
  if(! n %in% names(validDns.ngrams)) {
    totalDns.ngrams[[n]] = -100
  }
  # ONLY-VALID CASE
  else if(! n %in% names(evilDns.ngrams)) {
    totalDns.ngrams[[n]] = 100
  }
  # BOTH-VALID CASE
  else {
    totalDns.ngrams[[n]] = validDns.ngrams[[n]] - evilDns.ngrams[[n]] - totalDns.factor + 1
  }
}
totalDns.ngrams = totalDns.ngrams[order(unlist(totalDns.ngrams), decreasing = TRUE)]
totalDns.ngrams.frame = data.frame(
  ngram = names( totalDns.ngrams),
  prob  = unlist(totalDns.ngrams)
)
write.table(x = totalDns.ngrams.frame, file = "dns-freqs.csv", quote = FALSE, row.names = FALSE, col.names = FALSE)

##################################
####  Testy klasyfikatora     ####
##################################

isValidDns <- function(d, allNgrams) {
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
  return(prob > 0)
}

testDns.truePositives = 0;
testDns.trueNegatives = 0;
testDns.falsePositives = 0;
testDns.falseNegatives = 0;
testDns.i = 0
testDns.pb = txtProgressBar(min = 0, max = length(validDns.domains), initial = 0)
print("Checking valid class...")
for(d in validDns.domains) {
  if(isValidDns(toString(d), totalDns.ngrams)) {
    testDns.truePositives = testDns.truePositives + 1
  }
  else {
    testDns.falseNegatives = testDns.falseNegatives + 1
  }
  testDns.i = testDns.i + 1
  setTxtProgressBar(testDns.pb, testDns.i)
}
close(testDns.pb)
testDns.i = 0
testDns.pb = txtProgressBar(min = 0, max = length(evilDns.domains), initial = 0)
print("Checking evil class...")
for(d in evilDns.domains) {
  if(! isValidDns(toString(d), totalDns.ngrams)) {
    testDns.trueNegatives = testDns.trueNegatives + 1
  }
  else {
    testDns.falsePositives = testDns.falsePositives + 1
  }
  testDns.i = testDns.i + 1
  setTxtProgressBar(testDns.pb, testDns.i)
}

print(paste0("True VALID-DNS rate:    ", round(10000 * testDns.truePositives / length(validDns.domains))/100, "%" ))
print(paste0("True INVALID-DNS rate:  ", round(10000 * testDns.trueNegatives / length(evilDns.domains))/100, "%" ))
print(paste0("False VALID-DNS rate:   ", round(10000 * testDns.falsePositives / length(evilDns.domains))/100, "%" ))
print(paste0("False INVALID-DNS rate: ", round(10000 * testDns.falseNegatives / length(validDns.domains))/100, "%" ))






