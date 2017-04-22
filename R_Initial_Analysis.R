#remove old objects for safety resons
rm(list=ls(all=TRUE))
#set seed to make analysis reproducible if any pseudo random number generator is used by any function
set.seed(123)
#utility function to glue together text without separator
glue<-function(...){paste(...,sep="")}
#read the local paths to different directories from an external file
source("workingDir.R")
#change to the data directory
setwd(dataDir)
#Read in data set describing known Tor exit nodes. 
#Source: http://torstatus.blutmagie.de/
tor.nodes <- read.csv("Tor_query_EXPORT.csv",header=TRUE,sep = ",",dec = ".")#,na.strings=c("","NA")
#change all inputs of type flag to a factor
flags.indexes<-grepl("Flag...", names(tor.nodes))
tor.nodes[,grepl("Flag...", names(tor.nodes))] <- lapply(tor.nodes[, flags.indexes],as.factor)
dim(tor.nodes)
#[1] 7414   25
str(tor.nodes)
# 'data.frame':	7414 obs. of  25 variables:
# $ Router.Name       : Factor w/ 6389 levels "00000000000X",..: 4537 1055 2465 5907 905 20 904 263 5545 1189 ...
# $ Country.Code      : Factor w/ 82 levels "A1","AE","AL",..: 79 66 57 20 57 20 57 57 33 57 ...
# $ Bandwidth..KB.s.  : int  63057 48697 43315 39869 38916 38703 36795 33756 33510 32363 ...
# $ Uptime..Hours.    : int  78 1028 690 177 2467 678 2467 77 1615 488 ...
# $ IP.Address        : Factor w/ 7158 levels "1.234.11.142",..: 5076 1448 2331 1922 3797 4502 3796 5029 5265 2329 ...
# $ Hostname          : Factor w/ 7066 levels ".","0.tor.exit.babylon.network",..: 6712 3374 6431 988 1895 6067 1894 4919 6690 3514 ...
# $ ORPort            : int  443 9001 443 443 8081 9001 8080 443 443 9003 ...
# $ DirPort           : Factor w/ 543 levels "10001","10002",..: 420 302 420 475 476 475 475 420 420 429 ...
# $ Flag...Authority  : Factor w/ 2 levels "0","1": 1 1 1 1 1 1 1 1 1 1 ...
# $ Flag...Exit       : Factor w/ 2 levels "0","1": 2 2 2 2 2 1 2 2 1 1 ...
# $ Flag...Fast       : Factor w/ 2 levels "0","1": 2 2 2 2 2 2 2 2 2 2 ...
# $ Flag...Guard      : Factor w/ 2 levels "0","1": 2 2 2 1 2 2 2 2 2 2 ...
# $ Flag...Named      : Factor w/ 1 level "0": 1 1 1 1 1 1 1 1 1 1 ...
# $ Flag...Stable     : Factor w/ 2 levels "0","1": 2 2 2 2 2 2 2 2 2 2 ...
# $ Flag...Running    : Factor w/ 1 level "1": 1 1 1 1 1 1 1 1 1 1 ...
# $ Flag...Valid      : Factor w/ 1 level "1": 1 1 1 1 1 1 1 1 1 1 ...
# $ Flag...V2Dir      : Factor w/ 2 levels "0","1": 2 2 2 2 2 2 2 2 2 2 ...
# $ Platform          : Factor w/ 155 levels "Tor 0.2.4.19 on Windows XP",..: 102 102 145 102 59 145 59 152 127 102 ...
# $ Flag...Hibernating: Factor w/ 2 levels "0","1": 1 1 1 1 1 1 1 1 1 1 ...
# $ Flag...Bad.Exit   : Factor w/ 2 levels "0","1": 1 1 1 1 1 1 1 1 1 1 ...
# $ FirstSeen         : Factor w/ 1404 levels "2000-01-01","2007-10-27",..: 1284 344 344 1397 1222 1168 1222 323 1302 686 ...
# $ ASName            : Factor w/ 1391 levels "- GB","25700 - SWIFT VENTURES Inc- US",..: 537 24 622 868 856 941 856 855 338 1128 ...
# $ ASNumber          : int  41665 60118 1101 395978 43350 8972 43350 43350 29278 1103 ...
# $ ConsensusBandwidth: Factor w/ 2026 levels "1","10","100",..: 79 1908 169 210 72 83 46 1081 1995 117 ...
# $ OrAddress         : Factor w/ 623 levels "[2001:1470:fff7:12:e0c5:f8ff:fea1:9be3]:443",..: 623 539 623 623 623 623 623 370 623 152 ...
# ind <- apply( df1 , 1 , function(x) any( x > 0 ) )

#this input should be of type numeric
tor.nodes$ConsensusBandwidth<-as.numeric(tor.nodes$ConsensusBandwidth)

#This input describes the time this host is known to the Tor network we should recode it into a numeric
#inout describing time (here I choose months)
tor.nodes$FirstSeen <- strptime(tor.nodes$FirstSeen,"%Y-%m-%d")
#typeof(tor.nodes$FirstSeen)
#newestDate<-max(tor.nodes$FirstSeen)
oldestDate<-min(tor.nodes$FirstSeen)
#newestDate - oldestDate 
#Time difference of 6315.958 days

#time difference in days since oldest date (I have to divide by 60*60*24 to convert from seconds to days)
tor.nodes$FirstSeen <- as.numeric(tor.nodes$FirstSeen - oldestDate) / 86400
summary(tor.nodes$FirstSeen)
#Min. 1st Qu.  Median    Mean 3rd Qu.    Max. 
#0    5641    6005    5864    6220    6316 
tor.nodes$FirstSeen <- log(tor.nodes$FirstSeen+1)

# get subset with malicious nodes
d.mal<-subset(tor.nodes,tor.nodes$Flag...Exit==1)
dim(d.mal)
# [1] 869  25

#**************************************************************************
# Select features which are relevant to determine if a node is malicious.
#**************************************************************************

#threshold of relative variable importance
importance.threshold<-3.0

#determine which columns are numeric and which are factors
data.type<-sapply(tor.nodes, class)
numeric.indexes<-data.type == "integer"
factor.indexes<-data.type == "factor"
#numeric.indexes
#FALSE  TRUE 
#21     4 
table(factor.indexes)
#factor.indexes
#FALSE  TRUE 
#4    21 

#First remove all variables and rows without variation

#Start with numeric features:
variances.columns<-apply(tor.nodes[numeric.indexes],2,var)
table(variances.columns==0)
#FALSE 
#4 
variances.rows<-apply(tor.nodes[numeric.indexes],1,var)
table(variances.rows==0)
#FALSE 
#7414

#Continue with the categorical features:
numberOfModalities<-function(x){length(unique(x))}
variances.columns<-apply(tor.nodes[factor.indexes],2,numberOfModalities)
table(variances.columns)
# variances.columns
# 1    2   82  155  543  623 1391 1404 2026 6389 7066 7158 
# 3    8    1    1    1    1    1    1    1    1    1    1
#Conclusion: There are some factors with many modalities and others with very few.
# Router.Name           Hostname         IP.Address 
# 6389               7066               7158 
#These three features are identifiers! So it does not make sense to use them anyway.
#
#Three flags have no variance they have to be excluded, too:
sort(variances.columns)[1:3]
# Flag...Named Flag...Running   Flag...Valid 
# 1              1              1 

#Other problematic categories are:
# Platform            DirPort          OrAddress             ASName          FirstSeen ConsensusBandwidth 
# 155                543                623               1391               1404               2026 

selected.inputs<-names(tor.nodes)[-c(1,5,6,13,15,16,22,25)]

table(variances.columns==0)
#FALSE   
#19   

tor.nodes$Flag...Exit <- as.numeric(tor.nodes$Flag...Exit)-1

require("gbm")
#fit the model
m1.gbm <- gbm (Flag...Exit ~ . ,
               distribution="bernoulli",
               verbose=FALSE,
               interaction.depth=4,#6
               shrinkage=0.001,#0.001
               n.trees = 5000,#3000
               data=subset(tor.nodes, select = selected.inputs))

#a table with variables:
#var: feature name
#rel.inf: relative importance measure
(ri<-summary(m1.gbm))
# var      rel.inf
# DirPort                       DirPort 33.979547847
# Country.Code             Country.Code 26.775799867
# Platform                     Platform 19.164232024
# Bandwidth..KB.s.     Bandwidth..KB.s. 12.345234689
# Flag...Fast               Flag...Fast  2.125882948
# ASNumber                     ASNumber  1.837809310
# ORPort                         ORPort  1.343794679
# FirstSeen                   FirstSeen  0.906545882
# Uptime..Hours.         Uptime..Hours.  0.635596669

#select data set with features having relative importance > threshold [%]
ri<-ri[ri$rel.inf>importance.threshold,]
(selected.features<- ri$var)
#[1] DirPort          Country.Code     Platform         Bandwidth..KB.s.

#plot the predicted values of label 
plot(m1.gbm,  type="response", i.var = "DirPort")
plot(m1.gbm,  type="response", i.var = "Country.Code")
plot(m1.gbm,  type="response", i.var = "Platform")

#****************************************************
#Handle the port nr as a numeric variable:
#
#This helps us to see if there is a numeric trend.
#****************************************************

tor.nodes$DirPort.numeric<-as.numeric(tor.nodes$DirPort)
selected.inputs<-names(tor.nodes)[-c(1,5,6,8,13,15,16,22,25)]

#fit the model
m2.gbm <- gbm (Flag...Exit ~ . ,
               distribution="bernoulli",
               verbose=FALSE,
               interaction.depth=4,#6
               shrinkage=0.001,#0.001
               n.trees = 5000,#3000
               data=subset(tor.nodes, select = selected.inputs))

#a table with variables:
#var: feature name
#rel.inf: relative importance measure
(ri<-summary(m2.gbm))
# var     rel.inf
# Country.Code             Country.Code 36.70300059
# Platform                     Platform 28.98452394
# Bandwidth..KB.s.     Bandwidth..KB.s. 17.90112003
# ASNumber                     ASNumber  3.96636048
# Flag...Fast               Flag...Fast  3.72120191
# DirPort.numeric       DirPort.numeric  2.80809571

#****************************************************
#Conclusion:
#If we treat DirPort as a numeric variable,
#it does not help to predict malicious nodes any more.
#This indicates that there is no trend, such as e.g.
#ports with a higher number are more likely to be 
#associated with malicious nodes.
#It is only the identity of nodes that count.
#****************************************************

# get the relationship
library(FactoMineR)
tor.nodes.mca<-MCA(tor.nodes.malicious.sub,quanti.sup = c(which(names(tor.nodes.malicious.sub)%in%c("Uptime..Hours.","ASNumber","ORPort"))),level.ventil = 0.2)

