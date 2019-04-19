#####################################
####    KLASYFIKATOR BAYESA      ####
####       DNS TUNNELLING        ####
####         TRENOWANIE          ####
####      Artur M. Brodzki       ####
#####################################

allSubStrings <- function(str, n = 3) {
  substring(str, 1:(nchar(str)-n+1), n:nchar(str))
}

setwd("/Users/artur/Projekty/kant-security/bayes/")
source("load-data.r")

trainNgrams = function(object, domains) {
  
  object.ngrams = list()
  object.pb = txtProgressBar(min = 0, 
                             max = length(domains),
                             initial = 0)
  object.i = 0
  object.nsubs = 0
  print("Counting ngrams...")
  for(d in domains) {
    for(ng in allSubStrings(d, 3)) {
      if(ng %in% names(object.ngrams)) {
        object.ngrams[[ng]] = object.ngrams[[ng]] + 1
      }
      else {
        object.ngrams[[ng]] = 1
      }
    }
    object.i = object.i + 1
    object.nsubs = object.nsubs + length(allSubStrings(d, 3))
    setTxtProgressBar(object.pb, object.i)
  }
  close(object.pb)
  
  print("Calculating probabilities...")
  object.pb = txtProgressBar(min = 0, 
                             max = length(object.ngrams),
                             initial = 0)
  object.i = 0
  for(ng in names(object.ngrams)) {
    object.ngrams[[ng]] = 
      log( object.ngrams[[ng]] / object.nsubs, base = 2 )
    setTxtProgressBar(object.pb, object.i)
  }
  close(object.pb)
  
  object.ngrams = object.ngrams[order(unlist(object.ngrams), decreasing = TRUE)]
  print("All done!")
  return(object.ngrams)
}

validDns.ngrams = trainNgrams(validDns, validDns.domains)
evilDns.ngrams  = trainNgrams(evilDns, evilDns.domains)



###########################
# Baza wszystkich ngramów #
###########################

# Because cost of false negative 
# is many times higher then cost of false positive,
# probability scaling factor is introduced.
# It specifies, how many times 
# is probability of negative class higher 
# than probability of positive class
# to classify query as negative. 
trainDnsBayes = function(validNgrams, evilNgrams, factor) {
  
  totalDns.names = sample(c( names(validNgrams), names(evilNgrams) ))
  totalDns.ngrams = list()
  
  totalDns.i = 0
  totalDns.pb = txtProgressBar(min = 0, 
                               max = length(totalDns.names), 
                               initial = 0)
  for(n in totalDns.names) {
    # ONLY-EVIL VASE
    if(! n %in% names(validNgrams)) {
      totalDns.ngrams[[n]] = -factor
    }
    # ONLY-VALID CASE
    else if(! n %in% names(evilNgrams)) {
      totalDns.ngrams[[n]] = factor
    }
    # BOTH-VALID CASE
    else {
      totalDns.ngrams[[n]] = 
        validNgrams[[n]] - evilNgrams[[n]] + log(factor, base = 2)
    }
    totalDns.i = totalDns.i + 1
    setTxtProgressBar(totalDns.pb, totalDns.i)
  }
  close(totalDns.pb)
  totalDns.ngrams = totalDns.ngrams[order(names(totalDns.ngrams), decreasing = FALSE)]
  return(totalDns.ngrams)
  
}

# Learn final classifier
dnsBayes.ngrams = trainDnsBayes(validDns.ngrams, evilDns.ngrams, 20)
# Write results to file
dnsBayes.ngrams.frame = data.frame(
  ngram = names( dnsBayes.ngrams),
  prob  = unlist(dnsBayes.ngrams)
)
write.table(
  x = dnsBayes.ngrams.frame, 
  file = "dns.freqs", 
  quote = FALSE, 
  row.names = FALSE, 
  col.names = FALSE,
  sep = ","
)



