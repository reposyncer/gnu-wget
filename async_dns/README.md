# Wget2 Asynchronous DNS Resolver on Background Test

# Overview

  For general information please see the Wget2 User Manual

# Test

  Using a c-ares proof-of-concept, the script `test.sh` and a list of domains
  we aim to find optimal values for timeout, maximum number of tries on a given
  domain and the maximum number of parallel DNS queries.

# Dependencies

  - c-ares (libc-ares-dev package on Debian GNU/Linux; Otherwise https://c-ares.haxx.se/)
  - bash (to run the script)
  - gcc (to compile the PoC)
  - R (optional; if you want to build the graphics)

# Setting up

## Compile the PoC

  `gcc -Wall async_dns.c -o async_dns -lcares`
  Once compiled you can run it:
  `./async_dns MAXWAITING TIMEOUT MAXTRIES SOURCE DEST`
  Where:
  - MAXWAITING is the maximum number of simultaneous parallel DNS queries
  - TIMEOUT is the timeout for DNS queries
  - MAXTRIES is the number of attempts to make for each domain
  - SOURCE is the text file that contains the domain list
  - DEST is the (CSV) file in which results will be appended

## Domains List Structure

  The text file of the domains list must have a domain per line with the format
  "NAME.TLD" (it's case insensitive). One example:
  ```
  GNU.ORG
  FSF.ORG
  ```

## The Bash Script

  The script will execute the binary `async_dns` with `test` as domains list
  file and `file.csv` as the destination of the data. If you don't want to
  rename your files you can edit the BIN, SOURCE and DEST variables at the
  beginning of `test.sh`. If you modify the default destination file you'll
  also have to modify `create_graphics.R`.

## R Dependencies

  The package "ggplot2" has to be installed if you want to build the graphics.
  One way to do this is open R as superuser and type `install.packages("ggplot2")`

# Running the test

  You just have to type `bash test.sh` into your terminal. It'll build both the
  data and the graphics. Please be aware that it usually takes 24-48 hours to
  collect all the data (depends on the connection, changes made to the
  shellscript, ...). Once you have the data you can create again the graphics
  (if needed) in a few seconds just typing `Rscript create_graphics.R`
