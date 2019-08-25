#!/bin/bash

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

BIN=async_dns
SOURCE=test
DEST=file.csv
MAXWAITING=10
MAXWAITING_MOD=50
TIMEOUT_MOD=1000
MAXTRIES_MOD=1
while [ $MAXWAITING -le 1000 ];
do
	TIMEOUT=1000
	while [ $TIMEOUT -le 4000 ]
	do
		MAXTRIES=2
		while [ $MAXTRIES -le 5 ]
		do
			echo Running $MAXWAITING $TIMEOUT $MAXTRIES
			./$BIN $MAXWAITING $TIMEOUT $MAXTRIES $SOURCE $DEST
			let MAXTRIES=MAXTRIES+1
		done
		let TIMEOUT=TIMEOUT+TIMEOUT_MOD
	done
	let MAXWAITING=MAXWAITING+MAXWAITING_MOD
done
Rscript create_graphics.R
