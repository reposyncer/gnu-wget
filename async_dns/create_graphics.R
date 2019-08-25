# Copyright(c) 2019 Free Software Foundation, Inc.
#
# This file is part of GNU Wget.
#
# Wget is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Wget is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Wget.  If not, see <https://www.gnu.org/licenses/>.

library("ggplot2")
library("gridExtra")

data <- read.csv("file.csv")

pdf("results.pdf")

# range of values in MAXTRIES
x <- 2:5
for (i in x) {
	databuf <- data[c(which(data $ MAXTRIES == i)),]
	graphic1 <- ggplot(databuf[,c(1,2,6)], aes(x=MAXWAITING,y=TIME.sec.,colour=factor(TIMEOUT))) + ggtitle(paste("Async DNS resolver time results, when MAXTRIES =", i)) + geom_freqpoly(stat = "identity")
	ggsave(paste("time_", i, ".png", sep = ""));
	graphic2 <- ggplot(databuf[,c(1,2,4)], aes(x=MAXWAITING,y=RESOLVED,colour=factor(TIMEOUT))) + ggtitle(paste("Async DNS resolved results, when MAXTRIES =", i)) + geom_freqpoly(stat = "identity")
	ggsave(paste("resolved_", i, ".png", sep = ""))
	graphic <- grid.arrange(graphic1, graphic2, nrow=2)
	# print to a new pdf page
	print(graphic)
}
