/* Test of condition variables in multithreaded situations.
	Copyright (C) 2008-2022 Free Software Foundation, Inc.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <threads.h>

#include <wget.h>

static int
	cond_value = 0;
static mtx_t
	lockcond;
static cnd_t
	condtest;

static int cond_routine(WGET_GCC_UNUSED void *arg)
{
	mtx_lock(&lockcond);
	while (!cond_value)
		cnd_wait(&condtest, &lockcond);
	mtx_unlock(&lockcond);

	cond_value = 2;

	return 0;
}

static void test_cond(void)
{
	int remain = 1;
	thrd_t thread;

	cond_value = 0;

	mtx_init(&lockcond, mtx_plain);
	cnd_init(&condtest);

	thrd_create(&thread, cond_routine, NULL);
	do {
//		yield();
		remain = sleep(remain);
	} while (remain);

	/* signal condition */
	mtx_lock(&lockcond);
	cond_value = 1;
	cnd_signal(&condtest);
	mtx_unlock(&lockcond);

	thrd_join(thread, NULL);

	cnd_destroy(&condtest);
	mtx_destroy(&lockcond);

	if (cond_value != 2)
		exit(EXIT_FAILURE);
}

int main(void)
{
/*	if (!wget_thread_support())
		return 77;
*/
	test_cond();

	return 0;
}
