/*
CVSS
Copyright (C) 2023 Jon Hood <jwh0011@auburn.edu>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "cvss.h"
#include "cvss_3.h"
#include "cvss_3_1.h"
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>

using namespace std;

int main(int argc, char *argv[])
{
	bool baseScore = false;
	bool temporalScore = false;
	bool environmentalScore = false;

	string tmpCvssVersion = "3.1";

	for (int i2 = 1; i2 < argc; i2++)
	{
		string arg(argv[i2]);
		transform(arg.begin(), arg.end(), arg.begin(), ::toupper);

		if ((arg.rfind("-H", 0) == 0) || (arg.rfind("--HELP", 0) == 0))
		{
			cout << "Usage: ./cvss \"[CVSS Vector String]\"" << endl;
			cout << endl;
			cout << " -a  Display base, temporal, and environmental score." << endl;
			cout << " -b  Display base score." << endl;
			cout << " -t  Display temporal score." << endl;
			cout << " -e  Display environmental score." << endl;
		}
		else if ((arg.rfind("-A", 0) == 0))
		{
			baseScore = true;
			temporalScore = true;
			environmentalScore = true;
		}
		else if ((arg.rfind("-B", 0) == 0))
		{
			baseScore = true;
		}
		else if ((arg.rfind("-T", 0) == 0))
		{
			temporalScore = true;
		}
		else if ((arg.rfind("-E", 0) == 0))
		{
			environmentalScore = true;
		}
		else
		{
			return Parse(arg, baseScore, temporalScore, environmentalScore);
		}
	}
	return EXIT_FAILURE;
}
